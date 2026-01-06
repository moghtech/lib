export * as Types from "./types.js";

export function MoghAuthClient(url: string) {
  const request = <Params, Res>(
    type: string,
    params: Params
  ): Promise<Res> =>
    new Promise(async (res, rej) => {
      try {
        let response = await fetch(`${url}/${type}`, {
          method: "POST",
          body: JSON.stringify(params),
          headers: {
            // ...(state.jwt
            //   ? {
            //       authorization: state.jwt,
            //     }
            //   : state.key && state.secret
            //   ? {
            //       "x-api-key": state.key,
            //       "x-api-secret": state.secret,
            //     }
            //   : {}),
            "content-type": "application/json",
          },
          credentials: "include",
        });
        if (response.status === 200) {
          const body: Res = await response.json();
          res(body);
        } else {
          try {
            const result = await response.json();
            rej({ status: response.status, result });
          } catch (error) {
            rej({
              status: response.status,
              result: {
                error: "Failed to get response body",
                trace: [JSON.stringify(error)],
              },
              error,
            });
          }
        }
      } catch (error) {
        rej({
          status: 1,
          result: {
            error: "Request failed with error",
            trace: [JSON.stringify(error)],
          },
          error,
        });
      }
    });
}
