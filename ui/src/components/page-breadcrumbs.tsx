import { Breadcrumbs, BreadcrumbsProps, Text, TextProps } from "@mantine/core";
import { ReactNode } from "react";
import { Link } from "react-router-dom";

export interface Crumb extends TextProps {
  label: ReactNode;
  to?: string;
}

export interface PageBreadcrumbsProps extends Omit<
  BreadcrumbsProps,
  "children"
> {
  items: Crumb[];
  commonTextProps?: TextProps;
}

/**
 * The line height of a crumb's text. `Breadcrumbs` gives each crumb a
 * line height of 1, and a truncated crumb clips what overflows it:
 * that cut the descenders (a g, a p) off the label. `normal` is the
 * font's own height, which fits its glyphs.
 */
const CRUMB_LINE_HEIGHT = "normal";

export function PageBreadcrumbs({
  items,
  commonTextProps,
  ...breadcrumbsProps
}: PageBreadcrumbsProps) {
  return (
    <Breadcrumbs separatorMargin="xs" visibleFrom="sm" {...breadcrumbsProps}>
      {items.map(({ label, to, ...textProps }, i) =>
        to ? (
          <Text
            key={i}
            className="hover-underline"
            c="dimmed"
            fz="md"
            lh={CRUMB_LINE_HEIGHT}
            maw={200}
            truncate
            renderRoot={(props) => <Link to={to} {...props} />}
            {...commonTextProps}
            {...textProps}
          >
            {label}
          </Text>
        ) : (
          <Text
            key={i}
            fz="md"
            lh={CRUMB_LINE_HEIGHT}
            maw={200}
            truncate
            {...commonTextProps}
            {...textProps}
          >
            {label}
          </Text>
        ),
      )}
    </Breadcrumbs>
  );
}
