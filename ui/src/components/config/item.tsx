import {
  Button,
  createPolymorphicComponent,
  Group,
  PasswordInput,
  PasswordInputProps,
  Select,
  SelectProps,
  Stack,
  StackProps,
  SwitchProps,
  Text,
  TextInput,
  TextInputProps,
} from "@mantine/core";
import { forwardRef, ReactNode } from "react";
import { fmtSnakeCaseToUpperSpaceCase } from "../../formatting";
import { EnableSwitch } from "../enable-switch";
import { InputList, InputListProps } from "../input-list";
import { Plus } from "lucide-react";

// https://mantine.dev/guides/polymorphic/#create-your-own-polymorphic-components

export interface ConfigItemProps extends StackProps {
  label?: ReactNode;
  labelExtra?: ReactNode;
  description?: ReactNode;
  children?: ReactNode;
}

/**
 * The text a string `label` of a `ConfigItem` shows (snake case
 * spaced and capitalized), else `undefined`. The inputs of
 * `ConfigInput`, `ConfigSelector` and `ConfigSwitch` take it as their
 * accessible name by default: the item's label is no `<label>`.
 */
export function configItemLabel(label: ReactNode): string | undefined {
  return typeof label === "string"
    ? fmtSnakeCaseToUpperSpaceCase(label)
    : undefined;
}

export const ConfigItem = createPolymorphicComponent<"div", ConfigItemProps>(
  forwardRef<HTMLDivElement, ConfigItemProps>(
    ({ label, labelExtra, description, children, ...props }, ref) => {
      const labelDescription = (label || description) && (
        <Stack gap="0">
          {typeof label === "string" && (
            <Text fz="h3">{configItemLabel(label)}</Text>
          )}
          {label && typeof label !== "string" && label}
          {description && (
            // component="div" so ReactNode descriptions (Groups, nested Text)
            // don't produce invalid markup inside the default <p>.
            <Text c="dimmed" component="div">
              {description}
            </Text>
          )}
        </Stack>
      );
      return (
        <Stack {...props} ref={ref}>
          {labelExtra ? (
            <Group>
              {labelDescription}
              {labelExtra}
            </Group>
          ) : (
            labelDescription
          )}
          {children}
        </Stack>
      );
    },
  ),
);

export function ConfigInput({
  value,
  disabled,
  placeholder,
  onChange,
  onValueChange,
  onBlur,
  inputLeft,
  inputRight,
  inputProps,
  email,
  ...itemProps
}: {
  value: string | number | undefined;
  disabled?: boolean;
  placeholder?: string;
  onValueChange?: (value: string) => void;
  onBlur?: (value: string) => void;
  inputLeft?: ReactNode;
  inputRight?: ReactNode;
  inputProps?: TextInputProps;
  email?: boolean;
} & Omit<ConfigItemProps, "children">) {
  const inputNode = (
    <TextInput
      w={{ base: "85%", lg: 400 }}
      value={value}
      placeholder={placeholder}
      disabled={disabled}
      type={typeof value === "number" ? "number" : email ? "email" : undefined}
      onChange={(e) => {
        onChange?.(e);
        onValueChange?.(e.target.value);
      }}
      onBlur={(e) => onBlur?.(e.target.value)}
      aria-label={configItemLabel(itemProps.label)}
      {...inputProps}
    />
  );
  return (
    <ConfigItem {...itemProps}>
      {inputLeft || inputRight ? (
        <Group>
          {inputLeft}
          {inputNode}
          {inputRight}
        </Group>
      ) : (
        inputNode
      )}
    </ConfigItem>
  );
}

/**
 * A config field holding a credential (eg. a webhook secret, a url with
 * a token in it): masked, with a toggle to show it, so it isn't on
 * screen whenever the page is (a screen share, a recording). A
 * `Config` field with `secret: true` renders it, and keeps it out of
 * the confirm dialog; a custom field using it directly lists its key in
 * the Config's `secretKeys`.
 */
export function ConfigSecretInput({
  value,
  disabled,
  placeholder,
  onValueChange,
  inputProps,
  ...itemProps
}: {
  value: string | undefined;
  disabled?: boolean;
  placeholder?: string;
  onValueChange?: (value: string) => void;
  inputProps?: PasswordInputProps;
} & Omit<ConfigItemProps, "children">) {
  return (
    <ConfigItem {...itemProps}>
      <PasswordInput
        w={{ base: "85%", lg: 400 }}
        value={value ?? ""}
        placeholder={placeholder}
        disabled={disabled}
        onChange={(e) => onValueChange?.(e.target.value)}
        aria-label={configItemLabel(itemProps.label)}
        // Not the user's own password: a browser must not fill that in
        // (it ignores "off" on a password input).
        autoComplete="new-password"
        {...inputProps}
      />
    </ConfigItem>
  );
}

export function ConfigSelector({
  value,
  options,
  disabled,
  placeholder,
  onValueChange,
  onBlur,
  inputLeft,
  inputRight,
  inputProps,
  ...itemProps
}: {
  value: string | undefined;
  options?: { value: string; label?: string }[];
  disabled?: boolean;
  placeholder?: string;
  onValueChange?: (value: string) => void;
  onBlur?: (value: string) => void;
  inputLeft?: ReactNode;
  inputRight?: ReactNode;
  inputProps?: SelectProps;
} & Omit<ConfigItemProps, "children">) {
  const inputNode = (
    <Select
      w={{ base: "85%", lg: 400 }}
      value={value}
      data={options?.map(({ value, label }) => ({
        value,
        label: label ?? value,
      }))}
      placeholder={placeholder}
      disabled={disabled}
      onChange={(value) => {
        value && onValueChange?.(value);
      }}
      onBlur={(e) => onBlur?.(e.target.value)}
      aria-label={configItemLabel(itemProps.label)}
      {...inputProps}
    />
  );
  return (
    <ConfigItem {...itemProps}>
      {inputLeft || inputRight ? (
        <Group>
          {inputLeft}
          {inputNode}
          {inputRight}
        </Group>
      ) : (
        inputNode
      )}
    </ConfigItem>
  );
}

export function ConfigSwitch({
  value,
  disabled,
  onCheckedChange,
  switchProps,
  ...itemProps
}: {
  value: boolean | undefined;
  disabled: boolean;
  onCheckedChange: (value: boolean) => void;
  switchProps?: SwitchProps;
} & Omit<ConfigItemProps, "children">) {
  return (
    <ConfigItem {...itemProps}>
      <EnableSwitch
        checked={value}
        onCheckedChange={onCheckedChange}
        disabled={disabled}
        aria-label={configItemLabel(itemProps.label)}
        {...switchProps}
      />
    </ConfigItem>
  );
}

export function ConfigList<T>({
  addLabel,
  label,
  description,
  ...inputListProps
}: { label?: string; addLabel?: string } & InputListProps<T> &
  Omit<ConfigItemProps, "children">) {
  return (
    <ConfigItem label={label} description={description}>
      <InputList
        inputProps={{ w: { base: "85%", lg: 400 } }}
        {...inputListProps}
      />
      {!inputListProps.disabled && (
        <Button
          leftSection={<Plus size="1rem" />}
          onClick={() =>
            inputListProps.set({
              [inputListProps.field]: [...inputListProps.values, ""],
            } as Partial<T>)
          }
          w={{ base: "85%", lg: 400 }}
          disabled={inputListProps.disabled}
        >
          {addLabel ??
            (label
              ? "Add " + (label.endsWith("s") ? label.slice(0, -1) : label)
              : "Add")}
        </Button>
      )}
    </ConfigItem>
  );
}
