// Rendering for the jsdom tests (`*.test.tsx`): the providers an app
// puts around mogh_ui.

import { MantineProvider } from "@mantine/core";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, renderHook } from "@testing-library/react";
import type { ReactNode } from "react";
import { MemoryRouter } from "react-router-dom";

/**
 * The providers: a query client (by default as an app makes one, with
 * react-query's defaults), Mantine in test mode (no transitions, no
 * portals: a modal renders in place) and a router.
 */
export function providers(client = new QueryClient()) {
  return function Providers({ children }: { children: ReactNode }) {
    return (
      <QueryClientProvider client={client}>
        <MantineProvider env="test">
          <MemoryRouter>{children}</MemoryRouter>
        </MantineProvider>
      </QueryClientProvider>
    );
  };
}

export function renderWithProviders(ui: ReactNode, client?: QueryClient) {
  return render(ui, { wrapper: providers(client) });
}

export function renderHookWithProviders<R>(
  hook: () => R,
  client?: QueryClient,
) {
  return renderHook(hook, { wrapper: providers(client) });
}

/**
 * A `fetch` answering every request with `body` (json), `status` 200
 * unless given, and recording the requests.
 */
export function answering(body: unknown, status = 200) {
  const requests: { url: string; body: unknown }[] = [];
  const fetch = async (url: string, init?: RequestInit) => {
    requests.push({
      url,
      body: init?.body ? JSON.parse(String(init.body)) : undefined,
    });
    return new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    });
  };
  return { fetch, requests };
}
