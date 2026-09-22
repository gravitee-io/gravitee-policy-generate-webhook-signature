# 1.0.0 (2026-09-22)


### Bug Fixes

* default the additional-headers delimiter in the configuration class ([16853d9](https://github.com/gravitee-io/gravitee-policy-generate-webhook-signature/commit/16853d91de94c975a89bfc1bdec2ad67a5bb7bad))
* evaluate the error handlers lazily ([b61afe6](https://github.com/gravitee-io/gravitee-policy-generate-webhook-signature/commit/b61afe645eeb499a4ad277a78d8cca427edefac3))
* handle a missing timestamp header instead of letting it escape ([36efd2a](https://github.com/gravitee-io/gravitee-policy-generate-webhook-signature/commit/36efd2a122277a138783947b5e202ebed546170b))
* lower the per-request and per-message trace to debug ([7add34c](https://github.com/gravitee-io/gravitee-policy-generate-webhook-signature/commit/7add34c20808b63aea6cba00c083746532c5c19f))
* reject the response when the signature cannot be computed ([8e3deb3](https://github.com/gravitee-io/gravitee-policy-generate-webhook-signature/commit/8e3deb326028d898699a49688fc003e9bf9e5eaa))


### Features

* add optional timestamp-based replay protection ([42fca00](https://github.com/gravitee-io/gravitee-policy-generate-webhook-signature/commit/42fca005297317d18a3be85d3ec96fe905097a5d))
