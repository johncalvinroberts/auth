# Authentication core
The core part of the codebase provides base implementations that can be used by the first and third party guards and providers.

These base implementations must not be used inside the user-land code and the main purpose is to provide ready to use abstractions for guards and providers.

If you decide to contribut additional implementations, make sure to mark them as `abstract` to avoid direct usage.
