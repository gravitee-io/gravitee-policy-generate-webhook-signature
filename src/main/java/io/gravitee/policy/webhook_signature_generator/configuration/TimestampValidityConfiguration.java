/**
 * Copyright (C) 2025 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.policy.webhook_signature_generator.configuration;

import lombok.Getter;
import lombok.Setter;

/**
 * @author Brent HUNTER (brent.hunter at graviteesource.com)
 * @author GraviteeSource Team
 */
@Getter
@Setter
public class TimestampValidityConfiguration {

    // Optional - When enabled, a timestamp (epoch seconds) is generated, written to the targetTimestampHeader,
    // and prepended to the content used to compute the HMAC signature, allowing the receiver to detect replayed requests/messages
    private boolean enabled;

    private String targetTimestampHeader;

    // Delimiter placed between the generated timestamp and the rest of the signed content
    private String delimiter;
}
