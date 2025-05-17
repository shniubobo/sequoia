# Contributing to Sequoia PGP

Please take a moment to review this document in order to make the
contribution process easy and effective for everyone involved.

Following these guidelines helps to communicate that you respect the
time of the developers managing and developing this open source
project. In return, they should reciprocate that respect in
addressing your issue, assessing changes, and helping you finalize
your merge requests.

## Getting started

### Decide what you want to work on

If you are looking for something to work on, you can look through our
[issues](https://gitlab.com/sequoia-pgp/sequoia/issues) and pick some
you like. We try to maintain a list of issues that should be suitable
for first time contributions, they can be found tagged
[`good first contribution`](https://gitlab.com/sequoia-pgp/sequoia/-/issues/?label_name%5B%5D=good%20first%20contribution).

If you're still unsure, please contact us and we would help you to
the best of our abilities.


### Notify your interest

Please let us know you want to work on it so we can avoid multiple
people working on the same issue. Notify us via our
<a href="https://webchat.oftc.net/?nick=&channels=#sequoia">OFTC Webchat</a>, or
express your interest in the issue itself.

Before starting any large merge requests (like adding features or
reworking the code), **please ask first**. If you don't, you run the
risk of investing a lot of time in something that the project's
developers might decide not to include.


### Setting up the project in your local machine

1. [Fork](https://docs.gitlab.com/ee/user/project/repository/forking_workflow.html)
   the project, clone your fork, and configure the remotes:

  ```sh
    # Clone your fork of the repo into the current directory
    git clone https://gitlab.com/<your-username>/<repo-name>

    # Navigate to the newly cloned directory
    cd <repo-name>

    # Assign the original repo to a remote called "upstream"
    git remote add upstream https://gitlab.com/sequoia-pgp/<repo-name>
  ```

2. Create a new topic branch to contain your feature, change, or fix:

  ```sh
    git checkout -b <topic-branch-name>
  ```

3. Write clear and meaningful git commit messages. The commit message
   should be structured as follows:

  ```
    scope: <description>

    [optional body]
  ```

    A scope should be added to a commit’s type, to provide additional
    contextual information. Separate subject from body with a blank
    line and use the body to explain what changed and why.

    To find some examples, you can checkout the style of the commit
    messages on our [main branch](https://gitlab.com/sequoia-pgp/sequoia/-/commits/main).

4. Make sure to update or add to the tests when appropriate. Run the
   appropriate testing suites to check that all tests pass after
   you've made changes.

5. If you added or changed a feature, make sure to document it
   accordingly in the [README.md](./README.md) file, when appropriate.

#### Testing

Our tests are located in each package’s root directory.

To run **all tests**, run:
```
cargo test
```

To run **all tests within one crate**, do:
```
cargo test --tests -p sequoia-net
```
_Note:_ The name of the crate can be found at the `Cargo.toml` file
of the crate.


When you only want to run **one specific test file**, you can pass
the filename as a parameter, like:
```
cargo test --test hkp
```

You can additionally pass the name of any test function within that
file to run **only one test**:
```
cargo test --test hkp send
```


To see more options, you can visit the
[rust documentation](https://doc.rust-lang.org/cargo/commands/cargo-test.html)
or run `cargo --help`.


## Merge requests

Good merge requests - patches, improvements, new features - are a
fantastic help. They should remain focused in scope and avoid
containing unrelated commits.

1. Update your branch to the latest changes in the upstream main
   branch, solving conflicts if any appear. You can do that locally
   with:

```sh
  git pull --rebase upstream main
```

2. Push your topic branch up to your fork:

```sh
  git push origin <topic-branch-name>
```

3. [Open a Merge Request](https://docs.gitlab.com/ee/user/project/merge_requests/)
   with a clear title and a detailed description explaining the
   reasons for the changes. Make sure there is sufficient information
   for the reviewer to understand your changes.

4. Check if the CI/CD pipelines have passed. Address the errors if
   they have not.

🚨 **IMPORTANT**: By submitting a patch, you agree to license your
work under the same license as that used by the project.


### I have submitted my Merge Request, what are the next steps?

First of all, 🙏 thank you for your contribution! Sit back and relax.

As soon as possible, usually within a few weeks, a team member will
review your MR and provide comments.


## Reporting bugs

A bug is a _demonstrable problem_ that is caused by the code in our
repository. Good bug reports are extremely helpful!

A well-written bug report shouldn't require others to contact you
directly to obtain additional details. Kindly ensure that your report
contains as much detail as you can. What surrounds you? In what ways
can the problem be replicated? Which operating system is affected by
the issue? What result would you anticipate? All of these specifics
will aid in the correction of any possible bugs.

Before you create a bug report, you should:

1. **Use the GitLab issue search** - check if the issue has already
   been reported.

2. **Check if the issue has been fixed** - try to reproduce it using
   the latest `main` branch in the repository.

3. **Isolate the problem** - ideally create a reduced test case.

To create a new bug report, add a new
[issue](https://gitlab.com/sequoia-pgp/sequoia/issues).


### Report a security vulnerability

Please report security vulnerabilities to
<a href="mailto:security@sequoia-pgp.org">security@sequoia-pgp.org</a>
, preferably encrypted using this certificate:

<details>
  <summary>Click here to view the Public Key</summary>

  -----BEGIN PGP PUBLIC KEY BLOCK-----
  Comment: 6EFC 2689 8828 74C3 1E4F  C4EC 4D66 CB0F EBA5 DAF1
  Comment: security@sequoia-pgp.org

  xjMEX9DpCRYJKwYBBAHaRw8BAQdAWG3gIChzlo79zulsVYQFU5wySD+PZVRbMuHl
  IGX2FTzCwBEEHxYKAIMFgl/Q6QkFiQlmAYADCwkHCRBNZssP66Xa8UcUAAAAAAAe
  ACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmdzWyhXcksc6XRJFnUylyG6
  au1sGEr5Sy67X1pc4bLsYQMVCggCmwECHgEWIQRu/CaJiCh0wx5PxOxNZssP66Xa
  8QAAQnMBAP1fvOnMGs8OmuhDgcfuaEGJOdkDiX3clct/5Dyibym9AQCUgWxZoXV2
  pvDmzY/FwqJblZ++DcxC3Crub3+UBiIAC80Yc2VjdXJpdHlAc2VxdW9pYS1wZ3Au
  b3JnwsAUBBMWCgCGBYJf0OkJBYkJZgGAAwsJBwkQTWbLD+ul2vFHFAAAAAAAHgAg
  c2FsdEBub3RhdGlvbnMuc2VxdW9pYS1wZ3Aub3JnY2DIeOiQxRpmC2+d87v2loX4
  QvJy2gVHTM65xU+WA6sDFQoIApkBApsBAh4BFiEEbvwmiYgodMMeT8TsTWbLD+ul
  2vEAADgxAP9maacT175K14ZMgEiZ15dhm4+n5KoN5e7F5sWBvcjb/QD/WfwAx/Va
  DUU7omyRC2w/u2swLE8XN2+g5JofrNRrZwjOOARf0OkJEgorBgEEAZdVAQUBAQdA
  ES2OKI0Y7zefTNUUgp8TpDEt9HyqG8K1jBeRRZRqE1YDAQgJwsAJBBgWCgB7BYJf
  0OkJBYkJZgGACRBNZssP66Xa8UcUAAAAAAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1
  b2lhLXBncC5vcmeo6p8JahC+tYoa/QMgNeSRsFJfsI6aZNQpKLQ8w6KSHwKbhAIe
  ARYhBG78JomIKHTDHk/E7E1myw/rpdrxAAAYmAD/QP/xsyOqU7UKGczfKYQzaCj9
  EGpGL+fWV3w9dSUMSGIA+QGpTnAAJRkuGXbcOZ230oi3YiyjE4UpAiOPpqAGqcUJ
  =e55j
  -----END PGP PUBLIC KEY BLOCK-----

</details>


## Get in touch

Please do not hesitate to reach out! You can do so in our
<a href="https://webchat.oftc.net/?nick=&channels=#sequoia">OFTC Webchat</a>
, or send us an email.

To send an encrypted email to someone with a `sequoia-pgp.org` email
address, you can lookup their OpenPGP certificate using our WKD, like
so:

```sh
sq wkd get neal@sequoia-pgp.org
```

A number of people working in the OpenPGP space are involved in the
Sequoia project, and their OpenPG certificates can also be found on
our [community page](https://sequoia-pgp.org/community/).

All certificates are also certified using our OpenPGP CA certificate:

<details>
  <summary>Click here to view the Public Key</summary>

  -----BEGIN PGP PUBLIC KEY BLOCK-----
  Comment: 34F9 E4B6 A0A7 0BFE C5AE  4519 8356 989D F197 7575
  Comment: OpenPGP CA <openpgp-ca@sequoia-pgp.org>

  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
  =dVC0
  -----END PGP PUBLIC KEY BLOCK-----
</details>

You can use it to verify a certificate as follows:

```sh
$ sq wkd get openpgp-ca@sequoia-pgp.org
$ sq wkd get neal@sequoia-pgp.org
$ sq --trust-root 34F9E4B6A0A70BFEC5AE45198356989DF1977575 wot lookup --email neal@sequoia-pgp.org
[✓] 8F17777118A33DDA9BA48E62AACB3243630052D9 Neal H. Walfield <neal@sequoia-pgp.org>: fully authenticated (100%)
  ◯ 34F9E4B6A0A70BFEC5AE45198356989DF1977575 ("OpenPGP CA <openpgp-ca@sequoia-pgp.org>")
  │   certified the following binding on 2022-08-24
  └ 8F17777118A33DDA9BA48E62AACB3243630052D9 "Neal H. Walfield <neal@sequoia-pgp.org>"
```

To add our OpenPGP CA certificate as a CA for `sequoia-pgp.org` email
addresses, do:

```sh
$ sq link add --ca sequoia-pgp.org 34F9E4B6A0A70BFEC5AE45198356989DF1977575 "OpenPGP CA <openpgp-ca@sequoia-pgp.org>"
Linking 34F9E4B6A0A70BFEC5AE45198356989DF1977575 and "OpenPGP CA <openpgp-ca@sequoia-pgp.org>".
```


## License
Sequoia PGP is licensed under the terms of the LGPLv2+.

Contributions are governed by the Developer Certificate of Origin,
which can be obtained from [https://developercertificate.org/].  A
copy is reproduced below, for your convenience.

# Developer Certificate of Origin

```text
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```
