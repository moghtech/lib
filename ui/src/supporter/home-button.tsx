import { ReactNode } from "react";
import { Button, ButtonProps, Text } from "@mantine/core";
import { Link } from "react-router-dom";
import type { SupporterBrand } from "mogh_supporter";
import { SupporterBrandIcon, supporterIconHeight } from "./badge";

/**
 * How wide a brand's icon is at most on the compact home button: what
 * the topbar's icons on the right leave room for on a small screen.
 */
const COMPACT_MAX_WIDTH = "clamp(32px, calc(100vw - 340px), 110px)";

export interface SupporterHomeButtonProps extends Omit<
  ButtonProps,
  "children" | "leftSection" | "rightSection"
> {
  /**
   * `homeBrand` of `useSupporterBrand`: the brand of a verified
   * organization's or sponsor's key which takes the place of the app's
   * name and logo, or `null` for the app's own.
   */
  brand: SupporterBrand | null;
  /** The app's name, eg. `KOMODO`. Also the compact button's label. */
  wordmark: string;
  /**
   * The app's logo: shown without a brand, and with a brand which has
   * no icon (or while its icon fails to load).
   */
  logo: ReactNode;
  /** The logo's height in pixels, which the button makes room for. Default 32. */
  logoSize?: number;
  /**
   * The small screen variant: the logo (or the brand's icon) alone, at
   * most `compactMaxWidth` wide, the name its label.
   */
  compact?: boolean;
  /** Default `clamp(32px, calc(100vw - 340px), 110px)`. */
  compactMaxWidth?: number | string;
  /** Where it leads, a route of the app. Default `/`. */
  to?: string;
}

/**
 * The topbar's home button: the app's logo and name (`wordmark`), or
 * the brand of an organization's key whose branding puts it there
 * (`homeBrand` of `useSupporterBrand`), with the rules `SupporterBadge`
 * shows the brand by: its icon (the app's logo while it has none) at
 * the height the branding sets, which the button makes room for, its
 * name in capitals when the branding says so, or the icon alone with
 * the name as its label when the branding hides the name. A brand's
 * name gives way first where the topbar is short of room (cut with an
 * ellipsis), the app's name and an icon alone don't.
 *
 * Takes the props of the button it is, eg. `visibleFrom="md"`, and
 * `compact` for the small screen variant, eg. `hiddenFrom="md"`.
 */
export function SupporterHomeButton({
  brand,
  wordmark,
  logo,
  logoSize = 32,
  compact,
  compactMaxWidth = COMPACT_MAX_WIDTH,
  to = "/",
  ...buttonProps
}: SupporterHomeButtonProps) {
  // Room for a brand icon higher than the button. Without an icon of
  // its own, the brand keeps the app's logo.
  const iconHeight = (brand?.icon ? supporterIconHeight(brand) : logoSize) + 4;
  const icon = (maxWidth?: number | string) =>
    brand ? (
      <SupporterBrandIcon brand={brand} maxWidth={maxWidth} fallback={logo} />
    ) : (
      logo
    );
  const link = (props: Record<string, unknown>) => <Link to={to} {...props} />;

  if (compact) {
    const name = brand?.name ?? wordmark;
    return (
      <Button
        variant="subtle"
        renderRoot={link}
        px={2}
        h={Math.max(34, iconHeight)}
        flex="0 0 auto"
        aria-label={name}
        title={brand?.name}
        {...buttonProps}
      >
        {icon(compactMaxWidth)}
      </Button>
    );
  }

  const nameHidden = !!brand?.hideName;
  // Short of room, a brand's name is cut with an ellipsis. The app's
  // name and an icon standing alone are not: what is next to them (the
  // supporter badge) gives way instead.
  const shrinks = !!brand && !nameHidden;
  return (
    <Button
      variant="subtle"
      renderRoot={link}
      leftSection={nameHidden ? undefined : icon()}
      size="lg"
      px={nameHidden ? "xs" : undefined}
      h={Math.max(50, iconHeight)}
      miw={shrinks ? 0 : undefined}
      flex={shrinks ? "0 1 auto" : "0 0 auto"}
      aria-label={nameHidden ? brand?.name : undefined}
      title={nameHidden ? brand?.name : undefined}
      {...buttonProps}
    >
      {nameHidden ? (
        icon()
      ) : brand ? (
        <Text
          fz="h2"
          fw="450"
          truncate
          // In capitals, spaced like the app's name, when the
          // branding says so.
          tt={brand.uppercaseName ? "uppercase" : undefined}
          lts={brand.uppercaseName ? "0.1rem" : undefined}
        >
          {brand.name}
        </Text>
      ) : (
        <Text fz="h2" fw="450" lts="0.1rem">
          {wordmark}
        </Text>
      )}
    </Button>
  );
}
