// Reads an instance's recent CPU, memory and network usage from CloudWatch,
// for the resource-usage guard in ./usage.ts.
//
// - CPU and network come from the AWS/EC2 namespace, which every instance
//   reports without setup.
// - Memory is not visible from outside the VM. It is reported only if the
//   CloudWatch Agent runs on the instance (namespace CWAgent, metric
//   mem_used_percent, dimension InstanceId; see deploy/cloudwatch-agent.json).
//   Without the agent, memory comes back as null ("unknown"), never as 0.
//
// Each metric is reduced to its peak value inside the window. For a safety
// warning, the busiest recent period matters more than the average.
//
// The broker's own AWS identity needs cloudwatch:GetMetricData
// (iam/broker-read-metrics.json).

import {
  CloudWatchClient,
  GetMetricDataCommand,
  type MetricDataQuery,
} from "@aws-sdk/client-cloudwatch";

import type { Usage } from "./usage";

export interface MetricsOptions {
  region: string;
  /** How far back to look. Default 15 minutes (USAGE_WINDOW_MIN). */
  windowMinutes?: number;
  /**
   * Seconds per datapoint. 300 matches EC2's free basic monitoring; 60 needs
   * detailed monitoring enabled on the instance (USAGE_PERIOD_S).
   */
  periodSeconds?: number;
}

let client: CloudWatchClient | undefined;

export async function readUsage(instanceId: string, opts: MetricsOptions): Promise<Usage> {
  const windowMinutes = opts.windowMinutes ?? 15;
  const period = opts.periodSeconds ?? 300;
  client ??= new CloudWatchClient({ region: opts.region });

  const ec2 = (id: string, metric: string, stat: string, returnData = true): MetricDataQuery => ({
    Id: id,
    ReturnData: returnData,
    MetricStat: {
      Metric: {
        Namespace: "AWS/EC2",
        MetricName: metric,
        Dimensions: [{ Name: "InstanceId", Value: instanceId }],
      },
      Period: period,
      Stat: stat,
    },
  });

  const queries: MetricDataQuery[] = [
    ec2("cpu", "CPUUtilization", "Average"),
    // NetworkIn/Out are bytes per period. In + out, converted to Mbit/s.
    ec2("nin", "NetworkIn", "Sum", false),
    ec2("nout", "NetworkOut", "Sum", false),
    { Id: "net", Expression: "(nin + nout) * 8 / PERIOD(nin) / 1000000", ReturnData: true },
    {
      Id: "mem",
      ReturnData: true,
      MetricStat: {
        Metric: {
          Namespace: "CWAgent",
          MetricName: "mem_used_percent",
          Dimensions: [{ Name: "InstanceId", Value: instanceId }],
        },
        Period: period,
        Stat: "Average",
      },
    },
  ];

  const end = new Date();
  const start = new Date(end.getTime() - windowMinutes * 60_000);

  try {
    const out = await client.send(
      new GetMetricDataCommand({ MetricDataQueries: queries, StartTime: start, EndTime: end }),
    );
    const peak = (id: string): number | null => {
      const values = out.MetricDataResults?.find((r) => r.Id === id)?.Values ?? [];
      return values.length ? Math.max(...values) : null;
    };
    return { cpuPct: peak("cpu"), memPct: peak("mem"), netMbps: peak("net"), windowMinutes };
  } catch (err: any) {
    // Reported, not thrown: the guard treats "could not look" as "warn".
    return {
      cpuPct: null,
      memPct: null,
      netMbps: null,
      windowMinutes,
      readError: err?.name ?? err?.message ?? "unknown error",
    };
  }
}
