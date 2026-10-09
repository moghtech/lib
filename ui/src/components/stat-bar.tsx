import { Group, Progress, StackProps, Text } from "@mantine/core";
import { ReactNode } from "react";
import { hexColorByIntention } from "../color";
import { InfoCard } from "./info-card";
import { knownNumber } from "./known-number";

export interface StatBarProps extends StackProps {
  title: string;
  icon: ReactNode;
  description?: ReactNode;
  /** `undefined` (or not a finite number) while it isn't known. */
  percentage: number | undefined;
  warning: number | undefined;
  critical: number | undefined;
}

/**
 * A percentage (eg. CPU or memory usage) with its bar, coloured by its
 * `warning` / `critical` thresholds. An unknown one (`undefined`, eg. no
 * stats from an unreachable server, or not a finite number, eg. a used
 * over a total of 0) shows "N/A" with an empty bar: not a healthy
 * looking 0.00%, nor "NaN%".
 */
export function StatBar({
  title,
  icon,
  description,
  percentage: _percentage,
  warning: _warning,
  critical: _critical,
  ...props
}: StatBarProps) {
  const percentage = knownNumber(_percentage);
  const warning = _warning ?? 100;
  const critical = _critical ?? 100;
  const intent =
    percentage === undefined
      ? undefined
      : percentage > critical
        ? "Critical"
        : percentage > warning
          ? "Warning"
          : "Good";
  return (
    <InfoCard
      title={title}
      info={
        <Group gap="xs">
          <Text c={intent ? hexColorByIntention(intent) : "dimmed"} fz="lg">
            {percentage === undefined ? "N/A" : `${percentage.toFixed(2)}%`}
          </Text>
          {icon}
        </Group>
      }
      w={{ base: "100%", lg: 300 }}
      gap="0.2rem"
      justify="space-between"
      {...props}
    >
      {description && (
        <Text c="dimmed" size="sm">
          {description}
        </Text>
      )}
      <Progress color="bw" value={percentage ?? 0} size="xl" />
    </InfoCard>
  );
}
