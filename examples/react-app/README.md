# Example React application

The example shows the generated TypeScript client in a React application. It
reads the session, signs in with an email address and a password, requests a
sign-in link, and starts GitHub and Google sign-in.

The files are typechecked by the repository verification command:

```bash
just verify
```

## Files

| File | Content |
| --- | --- |
| `src/auth.ts` | The shared client instance. |
| `src/SignInForm.tsx` | The sign-in form and the provider links. |
| `src/App.tsx` | The session state of the application shell. |

## Notes

- The client sends the session cookie, so the API and the application share an
  origin in this example.
- An application on another origin needs
  `authall.WithTrustedOrigins("https://app.example.com")` on the server.
