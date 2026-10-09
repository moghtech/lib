import { Badge, Group, GroupProps, Switch, SwitchProps } from "@mantine/core";

export interface EnableSwitchProps extends SwitchProps {
  checked?: boolean;
  onCheckedChange?: (checked: boolean) => void;
  redDisabled?: boolean;
  labelProps?: GroupProps;
  /**
   * Enter toggles the switch as Space does, through its own change
   * handlers (`onChange` / `onCheckedChange`, eg. a form's
   * `getInputProps`), where it would submit the form around it. Once
   * per press: a held Enter doesn't flicker it.
   */
  toggleOnEnter?: boolean;
}

export function EnableSwitch({
  checked,
  color = "green.9",
  label,
  onChange,
  onCheckedChange,
  onKeyDown,
  disabled,
  redDisabled = true,
  labelProps,
  toggleOnEnter,
  ...props
}: EnableSwitchProps) {
  return (
    <Switch
      disabled={disabled}
      checked={checked}
      color={color}
      label={
        <Group gap="sm" wrap="nowrap" {...labelProps}>
          {label}
          <Badge
            color={checked ? color : redDisabled ? "red" : "gray"}
            opacity={disabled ? 0.7 : 1}
            style={{ cursor: disabled ? undefined : "pointer" }}
          >
            {checked ? "Enabled" : "Disabled"}
          </Badge>
        </Group>
      }
      onChange={(e) => {
        onChange?.(e);
        onCheckedChange?.(e.target.checked);
      }}
      onKeyDown={(e) => {
        onKeyDown?.(e);
        if (!toggleOnEnter || e.key !== "Enter" || e.defaultPrevented) {
          return;
        }
        // Handled here: not the form's submit, nor its key handlers.
        e.preventDefault();
        e.stopPropagation();
        // The click toggles the input, as Space does, which fires its
        // change: controlled or not, the switch and its form agree.
        if (!e.repeat) e.currentTarget.click();
      }}
      {...props}
    />
  );
}
