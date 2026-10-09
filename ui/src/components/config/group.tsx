import { Fragment } from "react";
import type { ConfigFieldArgs, ConfigGroupArgs } from ".";
import {
  ConfigInput,
  ConfigItem,
  configItemLabel,
  ConfigSecretInput,
  ConfigSelector,
  ConfigSwitch,
} from "./item";
import { Group, Stack } from "@mantine/core";
import { CircleQuestionMark } from "lucide-react";
import { ConfigNumberInput } from "./number-input";

export function ConfigGroup<T>({
  config,
  update,
  setUpdate,
  disabled,
  fields,
}: {
  config: T;
  update: Partial<T>;
  setUpdate: (update: Partial<T>) => void;
  disabled: boolean;
  fields: ConfigGroupArgs<T>["fields"];
}) {
  return (
    <Stack gap="xl">
      {Object.entries(fields).map(([key, field]) => {
        const value =
          (update as { [key: string]: unknown })[key] ??
          (config as { [key: string]: unknown })[key];
        if (typeof field === "function") {
          return <Fragment key={key}>{field(value, setUpdate)}</Fragment>;
        } else if (typeof field === "object" || field === true) {
          const args =
            typeof field === "object" ? (field as ConfigFieldArgs) : undefined;

          if (args?.hidden) {
            return null;
          }

          if (args?.secret) {
            // A string, also while it's unset.
            return (
              <ConfigSecretInput
                key={key}
                label={args.label ?? key}
                value={typeof value === "string" ? value : undefined}
                onValueChange={(value) =>
                  setUpdate({ [key]: value } as Partial<T>)
                }
                disabled={args.disabled || disabled}
                placeholder={args.placeholder}
                description={args.description}
                inputProps={{ error: args.error }}
              />
            );
          }

          switch (
            value !== undefined && value !== null ? typeof value : args?.type
          ) {
            case "string":
              if (args?.options) {
                return (
                  <ConfigSelector
                    key={key}
                    label={args?.label ?? key}
                    value={value as string}
                    options={args.options}
                    onValueChange={(value) =>
                      setUpdate({ [key]: value } as Partial<T>)
                    }
                    disabled={args?.disabled || disabled}
                    placeholder={args?.placeholder}
                    description={args?.description}
                    inputProps={{ error: args?.error }}
                  />
                );
              } else {
                return (
                  <ConfigInput
                    key={key}
                    label={args?.label ?? key}
                    value={value as string}
                    onValueChange={(value) =>
                      setUpdate({ [key]: value } as Partial<T>)
                    }
                    disabled={args?.disabled || disabled}
                    placeholder={args?.placeholder}
                    description={args?.description}
                    inputProps={{ error: args?.error }}
                  />
                );
              }

            case "number":
              return (
                <ConfigItem
                  key={key}
                  label={args?.label ?? key}
                  description={args?.description}
                >
                  <ConfigNumberInput
                    value={typeof value === "number" ? value : undefined}
                    onValueChange={(value) =>
                      setUpdate({ [key]: value } as Partial<T>)
                    }
                    disabled={args?.disabled || disabled}
                    placeholder={args?.placeholder}
                    aria-label={configItemLabel(args?.label ?? key)}
                    error={args?.error}
                  />
                </ConfigItem>
              );

            case "boolean":
              return (
                <ConfigSwitch
                  key={key}
                  label={args?.label ?? key}
                  value={value as boolean}
                  onCheckedChange={(value) =>
                    setUpdate({ [key]: value } as Partial<T>)
                  }
                  disabled={args?.disabled || disabled}
                  description={args?.description}
                  switchProps={{ error: args?.error }}
                />
              );

            default:
              return (
                <Group>
                  Config '{args?.label ?? key}':{" "}
                  <CircleQuestionMark size="1rem" />
                </Group>
              );
          }
        } else {
          return <Fragment key={key} />;
        }
      })}
    </Stack>
  );
}
