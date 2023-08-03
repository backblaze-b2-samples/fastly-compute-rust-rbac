# Role-Based Access Control at the Edge

Connect to an OpenID Connect identity provider such as Okta or Auth0 using OAuth 2.0, validate authentication status at the Edge, and authorize access to your edge or origin hosted applications.

This project is closely based on the [Compute@Edge OAuth application starter kit](https://github.com/fastly/compute-rust-auth) by the [Fastly](https://github.com/fastly) Developer Relations team. We created this application to demonstrate role-based access control (RBAC) in the [Access Control for Cloud Object Storage: Enforcing Policy at the Edge](https://developerweekcloudx2023.sched.com/event/1O5wp?iframe=no) conference session, presented at [DeveloperWeek CloudX](https://www.developerweek.com/cloudx/) in August 2023.

We added the following features to the original:

* Role-based Access Control - the app allows or denies requests to URL paths based on the authenticated user's group membership.
* A simple JavaScript single-page application (SPA) that demonstrates RBAC, along with sample resources.
* AWS V4 request signing to serve files from private buckets in S3-compatible cloud object storage platforms such as [Backblaze B2](https://www.backblaze.com/cloud-storage).
* Logout from the app, and single logout from the identity provider.

We used Okta as our identity provider for the demo; other OpenID Connect providers should work just as well.

## Authentication at Fastly's edge, using OAuth 2.0, OpenID Connect, and Compute@Edge

This is a self-contained Rust implementation 🦀  for the [OAuth 2.0](https://oauth.net/2/) [Authorization Code flow](https://oauth.net/2/grant-types/authorization-code/) with [Proof Key for Code Exchange (PKCE)](https://oauth.net/2/pkce/), deployed to [Compute@Edge](https://www.fastly.com/products/edge-compute/serverless/).

It includes [JSON Web Token (JWT)](https://oauth.net/2/jwt/) verification, and [access token introspection](https://oauth.net/2/token-introspection/).

![A simplified flow diagram of authentication using Compute@Edge](https://user-images.githubusercontent.com/12828487/111877689-4b876500-899c-11eb-9d6c-6ecc240fa317.png)

Scroll down to view [the flow in more detail](#the-flow-in-detail).

## Prerequisites

* A Backblaze B2 account - [sign up here](https://www.backblaze.com/b2/sign-up.html?referrer=nopref) if you do not already have one.
* A Fastly account - [sign up here](https://www.fastly.com/signup/).
* The [fastly command-line interface](https://developer.fastly.com/learning/tools/cli) (CLI). Follow the instructions to install the CLI and configure it with your Fastly API token.

## Getting Started

1. [Create a Backblaze B2 bucket](https://www.backblaze.com/docs/cloud-storage-create-and-manage-buckets). You can leave the privacy and other settings with their default values. Make a note of the **endpoint** shown in the bucket details. This has the form `s3.{your-bucket-region}.backblazeb2.com`, where `{your-bucket-region}` is the bucket's region, for example, `us-west-004`.
2. [Create an application key](https://www.backblaze.com/docs/cloud-storage-create-and-manage-app-keys#create-an-app-key) with read-only access to your bucket. Keep careful note of the application key ID and the application key itself. You will not be able to retrieve the application key value later!
3. Using the Fastly CLI, create a new project using this project template somewhere on your computer:

    ```shell
    fastly compute init --from=https://github.com/backblaze-b2-samples/devweek2023-demo
    ```

    Or click the button below to create a GitHub repository, provision a Fastly service, and set up continuous deployment:

    [![Deploy to Fastly](https://deploy.edgecompute.app/button)](https://deploy.edgecompute.app/backblaze-b2-samples/devweek2023-demo)

After you have created your project, you'll need to do some configuration before you can deploy it, so that Fastly knows which identity provider to use and how to authenticate.

### Set up an Identity Provider

You might operate your own identity service, but any [OAuth 2.0, OpenID Connect (OIDC) conformant provider](https://en.wikipedia.org/wiki/List_of_OAuth_providers) (IdP) will work.  You will need the following from your IdP:

* A *Client ID*, and possibly also a *Client Secret*, depending on the IdP -> Add to `src/config.toml`
* An *OpenID Connect Discovery document* -> Save as `src/well-known/openid-configuration.json`
* A *JSON Web key set* -> Save as `src/well-known/jwks.json`
* The hostname of the IdP's *authorization server* -> Create as a backend called `idp` on your Fastly service

As an example, if you are using Okta, follow these steps after installing the starter kit:

1. Sign up for an Okta Developer Edition: click "Sign up free for Developer Edition" at [https://developer.okta.com/signup/](https://developer.okta.com/signup/). Make a note of your Okta domain - this has the form `dev-12345678.okta.com`. You'll use this later as the _identity provider authorization server_ when you deploy the app to Fastly,
2. In the Okta Dashboard, in the left navigation bar, choose the **Applications** menu, then the **Applications** menu item, and click **Create App Integration**. Select **OIDC - OpenID Connect**, then **Web Application**, and click **Next**. Give your app a name and, under **Assignments**, select **Allow everyone in your organization to access** and _deselect_ **Enable immediate access with Federation Broker Mode**. Click **Save**.
   - The _client ID_ (eg. `0oaamq3it70DgCF2K5d7`) is shown in the **Client Credentials** section; a _client secret_ is listed in the **CLIENT SECRETS** section.
3. Edit your app's **Client Credentials** and select **Require PKCE as additional verification**. Click **Save**.
4. Click the **Sign On** tab, scroll down, and edit **OpenID Connect ID Token**. Set **Groups claim type** to _Filter_, and set **Groups claim filter** to _Matches regex_, with a regex of `.*` (all groups). Click **Save**.
5. Open `src/config.toml` in your Fastly project and paste in the `client_id` and `client_secret` from Okta.  Set the `nonce_secret` field to a long, non-guessable random string of your choice.  Save the file.
6. In a new tab, navigate to `https://{okta-domain}/.well-known/openid-configuration`.  Save it to `src/well-known/openid-configuration.json` in your Fastly project.
7. Open the file you just created and locate the `jwks_uri` property.  Fetch the document at that URL and save it to `src/well-known/jwks.json` in your Fastly project.

### Add Test Users to the Identity Provider

This app allows access to resources based on users' group membership. You will need to create a group, at least two test users, and assign one of the test users to the group.

1. In the Okta Dashboard, in the left navigation bar, choose the **Directory** menu, then the **Groups** menu item, and click **Add Group**. Name the group `accounting` (all lower case) and click **Save**. Refresh the browser page to see the new group.
2. In the left navigation bar, choose the **People** menu item, and click **Add Person**. Fill out first name, last name and username. Note that username must be in the form of an email, but it need not be a real email address. For example, you might use `alice@example.com`. Select **I will set password**, set a password for the user, and _deselect_ **User must change password on first login**. Click **Save and Add Another** and supply the same information for a second test user.
3. In the **People** list, click one of your test users, then click the **Groups** tab. Type `acc` into the field, and select `aacounting` from the drop-down list.  

### Deploy the Fastly service and get a domain

Now you can build and deploy your new service:

```term
$ fastly compute publish
```

You'll be prompted to enter the hostname of your own origin to configure the backend called `backend`, which you should set to `{your-bucket-name}.s3.{your-bucket-region}.backblazeb2.com`, and also the authorization server of the identity provider (for Okta, this is the Okta domain, with the form `dev-12345678.okta.com`) which will be used to configure a backend called `idp`.  When the deploy is finished you'll be given a Fastly-assigned domain such as `random-funky-words.edgecompute.app`.

### Link the identity provider to your Fastly domain

Add `https://{your-fastly-domain}/callback` to the list of allowed callback URLs in your identity provide's app configuration (In Okta, edit your application's **General Settings**, scroll down to **LOGIN**, add the callback URL to **Sign-in redirect URIs**, and click **Save**).

This allows the authorization server to send the user back to the Compute@Edge service.

### Create a Fastly Secret Store

The sample stores its Backblaze B2 credentials in a [secret store](https://developer.fastly.com/reference/api/services/resources/secret-store/). At present, the secret store feature is part of a beta release. Open a Fastly support ticket to request that secret store be enabled for your Fastly account.

Once the secret store feature is enabled for your account, create a secret store in the Fastly web UI:

* Click **Resources** in the top navigation menu.
* Click the **Secret stores** tab.
* Click **Create a secret store** and name it `devweek2023-demo`. 

Add the following key-value pairs:

* `B2_APPLICATION_KEY_ID`: your Backblaze B2 application key ID
* `B2_APPLICATION_KEY`: your Backblaze B2 application key

Link the secret store to your Fastly service:

* Click the **Link to services** button.
* Select your Fastly service.
* Click the **Next** button.
* Select **Link and activate**.
* Click **Confirm and activate** to link the secret store to a new version of the service and activate that version. 

Note - you may use an alternative name for your secret store. If you do so, you will need to change the value of the `FASTLY_SECRET_STORE` constant in [main.rs](https://github.com/backblaze-b2-samples/devweek2023-demo/blob/main/src/main.rs#L25). 

### Upload the Sample App Resources to B2

The repository contains sample resources in the `res` directory. You can copy these to your B2 bucket using either the Backblaze B2 CLI or the AWS CLI, as you prefer.

#### Using the Backblaze B2 CLI

1. [Install the Backblaze B2 CLI](https://www.backblaze.com/docs/en/cloud-storage-command-line-tools), if you do not already have it.
2. Authenticate to Backblaze B2 with the credentials you created earlier:
    ```shell
    b2 authorize-account "{application-key-id}" "{application-key}"
    ```
3. Use the `b2 sync` command to copy the contents of the `res` directory to your bucket. From your repository directory:
    ```shell
    b2 sync res b2://[your-bucket-name]/
    ```
4. Verify that the resources have been uploaded to B2: 
    ```shell
    b2 ls --recursive devweek2023-demo
    ```
    You should see the following listing:
    ```text
    accounting/accounts.pdf
    favicon.ico
    index.html
    internal.pdf
    logged-out.html
    public.html
    ```

#### Using the AWS CLI

1. [Install the AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html), if you do not already have it. Note that you will need version 2.13.0 or later for the next step. Older versions of the AWS CLI do not support configuration of the endpoint via an environment variable.
2. Configure the AWS CLI with your Backblaze B2 credentials and your bucket's endpoint via environment variables:
    ```shell
    export AWS_ACCESS_KEY_ID="{application-key-id}"
    export AWS_SECRET_ACCESS_KEY="{application-key}"
    export AWS_ENDPOINT_URL="https://s3.{your-bucket-region}.backblazeb2.com"
    ```
    There are [several other mechanisms for configuring the AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html#configure-precedence), but this is the most straightforward.
3. Use the `aws s3 sync` command to copy the contents of the `res` directory to your bucket. From your repository directory:
    ```shell
    aws s3 sync res s3://[your-bucket-name]/
    ```
4. Verify that the resources have been uploaded to B2:
    ```shell
    aws s3 ls --recursive s3://devweek2023-demo/
    ```
    You should see a listing like this:
    ```text
    2023-07-24 09:05:37      26599 accounting/accounts.pdf
    2023-07-28 09:39:34      85182 favicon.ico
    2023-07-24 09:05:37       3448 index.html
    2023-08-01 12:53:34      32227 internal.pdf
    2023-07-31 14:26:46       1286 logged-out.html
    2023-07-31 13:19:44       1388 public.html
    ```
   
### Try it out!

Now you can visit the sample app at your Fastly-assigned domain, the URL that looks like `https://random-funky-words.edgecompute.app`. You'll see a home page with the text, "You are not currently authenticated against your Okta org.".

1. At the home page, click the **Login** link. You will be redirected to Okta to login.
2. Log in as your `accounting` group member. You will be redirected back to a different home page, that greets the user by name and lists links to an "Internal doc" and an "Accounting doc".
3. Each of the docs is a PDF containing dummy text. Note that the accounting doc has restricted access - only members of the `accounting` group should be able to access that document! Make a note of both document URLs so you can paste them into the browser location bar later. They have the forms `https://random-funky-words.edgecompute.app/internal.pdf` and `https://random-funky-words.edgecompute.app/accounting/accounts.pdf`.
4. Click the **Logout** link. You will be redirected to Okta briefly, then straight back to the app.
5. Click the **Home** link. You will see the "not currently authenticated" message.
6. Now paste the `internal.pdf` link into the browser location bar and try to go to that page. You are redirected for login, since that document is restricted to authenticated users.
7. Log in as your other test user, which is not a member of the `accounting` group. You will see the internal PDF.
8. Delete `internal.pdf` from the end of the URL in your browser location bar to go back to your app's home page. Again, the test user is greeted by name, but this time only the internal doc is listed.
9. Paste the `accounting/accounts.pdf` link into the browser location bar and try to go to that page. You will see the message, "Access to /accounting directory denied!", since this user is not a member of the `accounting` group.


---

## The flow in detail

Here is how the authentication process works:

![Edge authentication flow diagram](https://user-images.githubusercontent.com/12828487/115379253-4438be80-a1c9-11eb-81af-9470e324434a.png)

1. The user makes a request for a protected resource, but they have no session cookie.
2. At the edge, this service generates:
   * A unique and non-guessable `state` parameter, which encodes what the user was trying to do (e.g., load `/internal.pdf`).
   * A cryptographically random string called a `code_verifier`.
   * A `code_challenge`, derived from the `code_verifier`.
   * A time-limited token, authenticated using the `nonce_secret`, that encodes the `state` and a `nonce` (a unique value used to mitigate replay attacks).
3. The `state` and `code_verifier` are stored in session cookies.
4. The service builds an authorization URL and redirects the user to the **authorization server** operated by the IdP.
5. The user completes login formalities with the IdP directly.
6. The IdP will include an `authorization_code` and a `state` (which should match the time-limited token we created earlier) in a post-login callback to the edge.
7. The edge service authenticates the `state` token returned by the IdP, and verifies that the state cookie matches its subject claim.
8. Then, it connects directly to the IdP and exchanges the `authorization_code` (which is good for only one use) and `code_verifier` for **security tokens**:
   * An `access_token` – a key that represents the authorization to perform specific operations on behalf of the user)
   * An `id_token`, which contains the user's profile information, including their group membership.
9. The end-user is redirected to the original request URL (`/internal.pdf`), along with their security tokens stored in cookies. The cookies are available to JavaScript running on pages served from the sample app, so the home page can display the user's name and list the accounting doc if appropriate.
10. When the user makes the redirected request (or subsequent requests accompanied by security tokens), the edge verifies the integrity, validity and claims for both tokens and, if the request URL contains a 'directory', verifies that the user is a member of a group with the same name as the directory. If the tokens are still good, and the user is allowed access to the URL, it proxies the request to your origin.

## Issues

If you encounter any bug or unexpected behavior, please [file an issue][bug]
using the bug report template.

[bug]: https://github.com/backblaze-b2-samples/devweek2023-demo/issues/new?labels=bug
