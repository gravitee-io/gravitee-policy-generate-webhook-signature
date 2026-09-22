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
package io.gravitee.policy.webhook_signature_generator;

import io.gravitee.el.TemplateEngine;
import io.gravitee.gateway.api.buffer.Buffer;
import io.gravitee.gateway.api.http.HttpHeaders;
import io.gravitee.gateway.reactive.api.ExecutionFailure;
import io.gravitee.gateway.reactive.api.context.http.HttpBaseExecutionContext;
import io.gravitee.gateway.reactive.api.context.http.HttpMessageExecutionContext;
import io.gravitee.gateway.reactive.api.context.http.HttpPlainExecutionContext;
import io.gravitee.gateway.reactive.api.message.Message;
import io.gravitee.gateway.reactive.api.policy.http.HttpPolicy;
import io.gravitee.policy.webhook_signature_generator.configuration.WebhookSignatureGeneratorPolicyConfiguration;
import io.reactivex.rxjava3.core.Completable;
import io.reactivex.rxjava3.core.Maybe;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.function.BiFunction;
import java.util.function.Function;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import lombok.extern.slf4j.Slf4j;

/**
 * @author Brent HUNTER (brent.hunter at graviteesource.com)
 * @author GraviteeSource Team
 */

@Slf4j
public class WebhookSignatureGeneratorPolicy implements HttpPolicy {

  private static final String WEBHOOK_SIGNATURE_ERROR =
    "WEBHOOK_SIGNATURE_ERROR";
  private static final String WEBHOOK_ADDITIONAL_HEADERS_NOT_VALID =
    "WEBHOOK_ADDITIONAL_HEADERS_NOT_VALID";

  /**
   * Policy configuration
   */
  private final WebhookSignatureGeneratorPolicyConfiguration configuration;

  public WebhookSignatureGeneratorPolicy(
    final WebhookSignatureGeneratorPolicyConfiguration configuration
  ) {
    this.configuration = configuration;
  }

  @Override
  public String id() {
    return "webhook-signature-generator";
  }

  // HTTP RESPONSE
  // **************
  @Override
  public Completable onResponse(HttpPlainExecutionContext ctx) {
    return ctx
      .response()
      .body()
      .flatMapCompletable(buffer ->
        validate(
          ctx,
          ctx.response().headers(),
          buffer,
          WebhookSignatureGeneratorPolicy::interrupt
        )
      )
      .onErrorResumeNext(th ->
        errorHandling(
          ctx,
          WEBHOOK_SIGNATURE_ERROR,
          th.toString(),
          WebhookSignatureGeneratorPolicy::interrupt
        )
      );
  }

  private <T extends HttpBaseExecutionContext> Completable validate(
    T ctx,
    HttpHeaders httpHeaders,
    Buffer buffer,
    BiFunction<T, ExecutionFailure, Completable> interrupt
  ) {
    log.info(
      "Executing WebhookSignatureGeneratorPolicy (in onResponse context)..."
    );

    String secret = ctx
      .getTemplateEngine()
      .getValue(configuration.getSecret(), String.class);
    String algorithm = configuration.getAlgorithm();
    String messageContent = buffer.toString();

    String signedContent;
    try {
      signedContent = prependAdditionalHeaders(
        messageContent,
        httpHeaders::get
      );
    } catch (IllegalArgumentException e) {
      log.error(e.getMessage());
      return errorHandling(
        ctx,
        WEBHOOK_ADDITIONAL_HEADERS_NOT_VALID,
        e.getMessage(),
        interrupt
      );
    }

    //Generate HMAC Signature
    String mySignature = generateHmacSignature(
      signedContent,
      secret,
      algorithm
    );

    return addSignatureToHeader(
      ctx.getTemplateEngine(),
      ctx.response().headers(),
      mySignature
    ).onErrorResumeNext(th ->
      errorHandling(
        ctx,
        WEBHOOK_SIGNATURE_ERROR,
        "Unable to process Signature Generator of HTTP Body!",
        interrupt
      )
    );
  }

  private <T extends HttpBaseExecutionContext> Completable errorHandling(
    T ctx,
    String key,
    String th,
    BiFunction<T, ExecutionFailure, Completable> interrupt
  ) {
    ctx.metrics().setErrorMessage(th);
    return interrupt.apply(ctx, new ExecutionFailure(500).key(key).message(th));
  }

  private static Completable interrupt(
    HttpPlainExecutionContext ctx,
    ExecutionFailure executionFailure
  ) {
    return ctx.interruptWith(executionFailure);
  }

  // MESSAGE RESPONSE
  // ****************
  @Override
  public Completable onMessageResponse(HttpMessageExecutionContext ctx) {
    return ctx
      .response()
      .onMessage(message -> generateSignatureForMessage(ctx, message));
  }

  private Maybe<Message> generateSignatureForMessage(
    final HttpMessageExecutionContext ctx,
    final Message message
  ) {
    log.info(
      "Executing WebhookSignatureGeneratorPolicy (in onMessageResponse context)..."
    );

    String secret = ctx
      .getTemplateEngine()
      .getValue(configuration.getSecret(), String.class);
    String algorithm = configuration.getAlgorithm();
    String messageContent = message.content().toString();

    String signedContent;
    try {
      signedContent = prependAdditionalHeaders(
        messageContent,
        message.headers()::get
      );
    } catch (IllegalArgumentException e) {
      log.error(e.getMessage());
      return ctx.interruptMessageWith(
        new ExecutionFailure(500)
          .key(WEBHOOK_ADDITIONAL_HEADERS_NOT_VALID)
          .message(e.getMessage())
      );
    }

    //Generate HMAC Signature
    String mySignature = generateHmacSignature(
      signedContent,
      secret,
      algorithm
    );

    return addSignatureToHeader(
      ctx.getTemplateEngine(message),
      message.headers(),
      mySignature
    )
      .andThen(Maybe.just(message))
      .onErrorResumeNext(th ->
        ctx.interruptMessageWith(
          new ExecutionFailure(500)
            .key(WEBHOOK_SIGNATURE_ERROR)
            .message("Unable to process Signature Generator in Message!")
        )
      );
  }

  // SUPPORTING CODE
  // ***************

  /**
   * Prepends the configured additional header values (each followed by the configured delimiter) to the given content.
   * Returns the content unchanged when the "additional headers" scheme is disabled.
   *
   * @throws IllegalArgumentException if the scheme is enabled but no headers are configured, or a configured header is missing
   */
  private String prependAdditionalHeaders(
    String content,
    Function<String, String> headerGetter
  ) {
    if (!configuration.getSchemeType().isEnabled()) {
      return content;
    }

    List<String> addedHeaders = new ArrayList<>(
      configuration.getSchemeType().getHeaders()
    );
    if (addedHeaders.isEmpty()) {
      throw new IllegalArgumentException(
        "Additional headers were specified, but unable to find any configured headers!"
      );
    }

    String headersDelimiter = configuration
      .getSchemeType()
      .getHeadersDelimiter();
    log.debug("Config> headersDelimiter: {}", headersDelimiter);

    StringBuilder prefix = new StringBuilder();
    for (String headerName : addedHeaders) {
      String headerValue = headerGetter.apply(headerName);
      log.debug(
        "Config> Prefixing header '{}' ({}) to content",
        headerName,
        headerValue
      );
      if (headerValue == null) {
        throw new IllegalArgumentException(
          "A specified header value is invalid or missing!"
        );
      }
      prefix.append(headerValue).append(headersDelimiter);
    }

    String result = prefix + content;
    log.debug(
      "Final content (prepended with additional header values): {}",
      result
    );
    return result;
  }

  private Completable addSignatureToHeader(
    final TemplateEngine templateEngine,
    final HttpHeaders httpHeaders,
    final String signature
  ) {
    log.debug(
      "Setting '{}' HTTP Header to '{}'",
      configuration.getTargetSignatureHeader(),
      signature
    );
    return Completable.fromRunnable(() ->
      httpHeaders.set(configuration.getTargetSignatureHeader(), signature)
    );
  }

  // Method to generate HMAC signature
  private String generateHmacSignature(
    String data,
    String secretKey,
    String algorithm
  ) {
    try {
      // Create a SecretKeySpec from the key
      SecretKeySpec secretKeySpec = new SecretKeySpec(
        secretKey.getBytes("UTF-8"),
        algorithm
      );

      // Initialize the Mac instance with the specified algorithm
      Mac mac = Mac.getInstance(algorithm);
      mac.init(secretKeySpec);

      // Generate the HMAC hash of the data
      byte[] hmacHash = mac.doFinal(data.getBytes("UTF-8"));

      log.debug(
        "Generated HMAC signature: {}",
        Base64.getEncoder().encodeToString(hmacHash)
      );

      // Return the Base64 encoded HMAC signature
      return Base64.getEncoder().encodeToString(hmacHash);
    } catch (Exception ex) {
      log.error("Exception occurred while generating HMAC signature!");
      log.error(ex.getMessage());
      return null;
    }
  }
}
