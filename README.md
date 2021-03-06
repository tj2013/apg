APG (Android Privacy Guard)
===========================

OpenPGP for Android.

I'd like to pick this up again, despite the awesome advances of the fork [OpenPGP-Keychain](https://github.com/openpgp-keychain/openpgp-keychain/). Those guys did a great job, but I differ in some of the implementation details and decisions, so I hope the projects can continue to benefit from each other.

APG definitely has some catching up to do. :)

## Build

### Requirements

* Android SDK 19.0.2
* Gradle 1.10

### Command line
```
> git submodule update --init
> git submodule foreach git submodule update --init
> gradle build
```

## Contributing
I definitely will need loads of help with this. However, for now I'll have to refactor most of the old code.

I think that is hard to parallelize... but drop me a line, if you fancy a go, perhaps we can work out some tasks that don't interfer with each other much.

### Branches
The **master** branch can be considered safe and "stable", that is... I won't change its history with merges or rebases.
**All other development branches are definitely subject to rebasing, commit reordering, and all sorts of other clean up action.**
So be advised. Should there be some explicit feature branches that require multiple contributors, then we can lock those down as well.
