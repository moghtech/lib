import {
  DropdownMenuContentProps,
  DropdownMenu as Root,
} from "@kobalte/core/dropdown-menu";
import { PolymorphicProps } from "@kobalte/core";
import { ValidComponent } from "solid-js";
import { cn } from "../utils";

function DropdownMenuContent<T extends ValidComponent = "div">(
  props: PolymorphicProps<T, DropdownMenuContentProps<T>>
) {
  return (
    <Root.Portal>
      <Root.Content class={cn()}>

      </Root.Content>
    </Root.Portal>
  );
}
