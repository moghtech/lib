/**
 * Loads the page again, as `AccountsMenu` does once it changed this
 * tab's account: everything the page holds for the previous user goes
 * with it. A module of its own (not exported from the package) so the
 * tests can tell it was called: jsdom implements no reload.
 */
export function reloadPage() {
  location.reload();
}
