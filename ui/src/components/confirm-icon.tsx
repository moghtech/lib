import {
  ActionIcon,
  ActionIconProps,
  createPolymorphicComponent,
  Loader,
} from "@mantine/core";
import { Check, CircleQuestionMark } from "lucide-react";
import {
  FocusEventHandler,
  forwardRef,
  MouseEventHandler,
  useEffect,
  useState,
} from "react";

// https://mantine.dev/guides/polymorphic/#create-your-own-polymorphic-components

export interface ConfirmIconProps extends ActionIconProps {
  onClick?: MouseEventHandler<HTMLButtonElement>;
  onBlur?: FocusEventHandler<HTMLButtonElement>;
  /**
   * What the button does (eg. "Remove from group"): its accessible
   * name and tooltip, "Confirm: <label>" while it waits for the
   * confirming click. Pass it: the icon alone names nothing.
   */
  label?: string;
}

/**
 * An icon button which asks for a second click (within 4 seconds) before
 * it runs `onClick`, showing a check mark in between.
 */
export const ConfirmIcon = createPolymorphicComponent<
  "button",
  ConfirmIconProps
>(
  forwardRef<HTMLButtonElement, ConfirmIconProps>(
    (
      { children, onClick, onBlur, miw, loading, disabled, label, ...props },
      ref,
    ) => {
      const [clickedOnce, setClickedOnce] = useState(false);
      useEffect(() => {
        if (clickedOnce) {
          const timeout = setTimeout(() => {
            setClickedOnce(false);
          }, 4_000);
          return () => clearTimeout(timeout);
        }
      }, [clickedOnce]);
      return (
        <ActionIcon
          onClick={(e) => {
            e.stopPropagation();
            if (clickedOnce) {
              onClick?.(e);
              setClickedOnce(false);
            } else {
              setClickedOnce(true);
            }
          }}
          onBlur={(e) => {
            setClickedOnce(false);
            onBlur?.(e);
          }}
          onPointerDown={(e) => e.stopPropagation()}
          disabled={disabled || loading}
          title={label}
          aria-label={label && (clickedOnce ? `Confirm: ${label}` : label)}
          {...props}
          ref={ref}
        >
          {clickedOnce ? (
            <Check size="1rem" />
          ) : loading ? (
            <Loader color="white" size="1rem" />
          ) : (
            (children ?? <CircleQuestionMark size="1rem" />)
          )}
        </ActionIcon>
      );
    },
  ),
);
