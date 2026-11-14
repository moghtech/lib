import {
  Button,
  ButtonProps,
  createPolymorphicComponent,
  Loader,
} from "@mantine/core";
import { Check, CircleQuestionMark } from "lucide-react";
import {
  FocusEventHandler,
  forwardRef,
  MouseEvent,
  MouseEventHandler,
  ReactNode,
  useEffect,
  useState,
} from "react";
import { useSingleFlight } from "../hooks";

// https://mantine.dev/guides/polymorphic/#create-your-own-polymorphic-components

export interface ConfirmButtonProps extends ButtonProps {
  icon?: ReactNode;
  onClick?: MouseEventHandler<HTMLButtonElement>;
  onBlur?: FocusEventHandler<HTMLButtonElement>;
  /** Passed when button is in confirm mode */
  confirmProps?: ButtonProps;
}

/**
 * A button which asks for a second click (within 4 seconds) before it
 * runs `onClick`, reading "Confirm" in between (with `confirmProps`).
 * `onClick` runs once per confirm (see `useSingleFlight`).
 */
export const ConfirmButton = createPolymorphicComponent<
  "button",
  ConfirmButtonProps
>(
  forwardRef<HTMLButtonElement, ConfirmButtonProps>(
    (
      {
        icon,
        rightSection,
        children,
        onClick,
        onBlur,
        miw,
        loading,
        disabled,
        confirmProps,
        ...props
      },
      ref,
    ) => {
      const [clickedOnce, setClickedOnce] = useState(false);
      // The confirming click runs `onClick` once: a click landing in
      // the same tick (eg. a double click on the confirm) still sees
      // `clickedOnce`, which React hasn't rendered away yet, and would
      // run it again. Also held while an `onClick` returning a promise
      // runs.
      const confirm = useSingleFlight(
        async (e: MouseEvent<HTMLButtonElement>) => await onClick?.(e),
      );
      useEffect(() => {
        if (clickedOnce) {
          const timeout = setTimeout(() => {
            setClickedOnce(false);
          }, 4_000);
          return () => clearTimeout(timeout);
        }
      }, [clickedOnce]);
      return (
        <Button
          onClick={(e) => {
            e.stopPropagation();
            if (clickedOnce) {
              void confirm(e);
              setClickedOnce(false);
            } else {
              setClickedOnce(true);
            }
          }}
          onBlur={(e) => {
            onBlur?.(e);
            setClickedOnce(false);
          }}
          justify="space-between"
          w={{ base: "100%", xs: 190 }}
          miw="fit-content"
          rightSection={
            clickedOnce ? (
              <Check size="1rem" />
            ) : loading ? (
              <Loader size="1rem" />
            ) : (
              (rightSection ?? icon ?? <CircleQuestionMark size="1rem" />)
            )
          }
          disabled={disabled || loading}
          {...props}
          {...(clickedOnce ? confirmProps : {})}
          ref={ref}
        >
          {clickedOnce ? "Confirm" : children}
        </Button>
      );
    },
  ),
);
