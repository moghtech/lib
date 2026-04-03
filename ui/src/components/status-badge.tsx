import { forwardRef } from "react";
import { Text, TextProps, createPolymorphicComponent } from "@mantine/core";
import { ColorIntention, hexColorByIntention } from "../color";
import { fmtUpperCamelcase, fmtSnakeCaseToUpperSpaceCase } from "../formatting";

// https://mantine.dev/guides/polymorphic/#create-your-own-polymorphic-components

interface StatusBadgeProps extends TextProps {
  text: string | undefined;
  intent: ColorIntention;
}

export const StatusBadge = createPolymorphicComponent<"div", StatusBadgeProps>(
  forwardRef<HTMLDivElement, StatusBadgeProps>(
    ({ text: _text, intent, ...props }, ref) => {
      if (!_text) {
        return null;
      }

      const text = fmtSnakeCaseToUpperSpaceCase(
        fmtUpperCamelcase(_text),
      ).toUpperCase();
      const _background = hexColorByIntention(intent);
      const background = _background ? _background + "25" : undefined;

      return (
        <Text
          fz={{ base: "xs", md: "sm" }}
          bdrs="md"
          w="fit-content"
          c={intent}
          bg={background}
          px="0.5rem"
          py="0.2rem"
          lts="0.025em"
          {...props}
          ref={ref}
        >
          {text}
        </Text>
      );
    },
  ),
);
