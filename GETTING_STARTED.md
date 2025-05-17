# Getting Started - A Guide for New Contributors

👋 **First off! Hello, and a warm welcome to the Sequoia PGP
project!**

We’re delighted that you’re interested in participating, and we want
to make it as pleasant and simple as we can, whether you want to send
a one-off merge request or you want to become part of the team in the
long run.

**If you’re new here and interested in any form of contribution, this
guide is for you.**

## What is Sequoia and what is it used for?

[Sequoia PGP](https://sequoia-pgp.org/) is a free implementation of
OpenPGP written in Rust. It is used to, for example, encrypt,
decrypt, sign, and verify OpenPGP messages. It aims to be complete as
defined in RFC 4880, and also provide some extensions.

It consists of several crates, providing both an unopinionated
(policy-free) low-level API as well as a more opinionated high-level
API for dealing with OpenPGP data. The former is quite complete, the
latter very much in progress.

Sequoia PGP can be used as a dependency in your sofware project, but
also provides a number of command-line tools, most importantly
[sq](https://gitlab.com/sequoia-pgp/sequoia-sq), which allows you to
easily experiment with Sequoia and OpenPGP.

Sequoia exists to improve the security of OpenPGP not only by
establishing a new, modern implementation in a memory- and type-safe
language, but also by improving the ecosystem by, for example,
[testing and ensuring widepread interoperability](https://tests.sequoia-pgp.org/)
between OpenPGP implementations.

The project is strongly user-oriented and pragmatic, aimed squarely
at identifying and fulfilling user needs. To ensure widespread
adpotion, Sequoia PGP is designed to be easy to use, and, at it’s
core, unopinionated about how you use OpenPGP.

...

## Everyone can contribute

An Open Source project such as this one has a wide range of needs
aside from coding and cryptography, and there are a lot of
opportunities to help:

- You can expand or improve the test suite
- You can take the project for a test drive and update the dev setup
  documentation for your platform (see [CONTRIBUTING.md](/CONTRIBUTING.md))
- You can improve the various documentation resources in general, for
  example by looking for
  [documentation issues](https://gitlab.com/sequoia-pgp/sequoia/-/issues/?label_name%5B%5D=doc)
  , or just picking something to expand upon, edit or check for typos
- You can improve the build process
- You can improve or maintain
  [our website](https://gitlab.com/sequoia-pgp/sequoia-web)
- You can evangelize for the project: present or talk about Sequoia
  PGP in your company, local tech meetup, youtube channel, or similar
  circles

## How do you get Started?

### Get Sequoia

Sequoia is maintained in a Git repository. To clone it, do:

```sh
git clone https://gitlab.com/sequoia-pgp/sequoia.git
```

### Build Sequoia
Please see
[https://gitlab.com/sequoia-pgp/sequoia#building-sequoia](https://gitlab.com/sequoia-pgp/sequoia#building-sequoia)
for build instructions.

There is also a
[guided tour through the Sequoia OpenPGP library](https://sequoia-pgp.org/guide/).
Please note that this guide as well as Sequoia is work in progress.
But, fear not! This guide is part of the API documentation, and the
code fragments are tested as part of Sequoias test suite. This makes
sure that this guide is always up-to-date.

### Getting your Bearings in the Sequoia PGP Project

We’ve got a bunch of helpful resources you might be interested in:

- There’s a
  <a href="https://webchat.oftc.net/?nick=&channels=#sequoia">OFTC Webchat</a>
  , which is a good place for establishing first contact with the
  project.
- Join our mailing list by sending a mail to
  <a href="mailto:devel-subscribe@lists.sequoia-pgp.org">
  devel-subscribe@lists.sequoia-pgp.org</a> or go to
  [lists.sequoia-pgp.org](https://lists.sequoia-pgp.org).
- **Our [Guide for Contributors](/CONTRIBUTING.md), which details
  topics such as project processes, code and commit conventions,
  expectations for MRs, as well as documentation on dev setup and
  testing.**
- And of course our
  [GitLab issues](https://gitlab.com/sequoia-pgp/sequoia/issues),
  where you can find tasks to take on. We try to have some
  [good first contribution](https://gitlab.com/sequoia-pgp/sequoia/issues/?label_name%5B%5D=good%20first%20contribution)
  for newcomers in place, but there might not always be some available.

All that’s left here is to thank you for your time and interest, and
we hope you’ll join us on our quest for a better OpenPGP implementation
and ecosystem! 🚀

👋
