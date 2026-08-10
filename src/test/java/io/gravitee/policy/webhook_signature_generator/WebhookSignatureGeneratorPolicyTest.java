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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

import io.gravitee.el.TemplateEngine;
import io.gravitee.gateway.api.buffer.Buffer;
import io.gravitee.gateway.api.http.HttpHeaders;
import io.gravitee.gateway.reactive.api.ExecutionFailure;
import io.gravitee.gateway.reactive.api.context.http.HttpMessageExecutionContext;
import io.gravitee.gateway.reactive.api.context.http.HttpMessageResponse;
import io.gravitee.gateway.reactive.api.context.http.HttpPlainExecutionContext;
import io.gravitee.gateway.reactive.api.context.http.HttpPlainResponse;
import io.gravitee.gateway.reactive.api.message.Message;
import io.gravitee.policy.webhook_signature_generator.configuration.SchemeTypeConfiguration;
import io.gravitee.policy.webhook_signature_generator.configuration.TimestampValidityConfiguration;
import io.gravitee.policy.webhook_signature_generator.configuration.WebhookSignatureGeneratorPolicyConfiguration;
import io.reactivex.rxjava3.core.Completable;
import io.reactivex.rxjava3.core.Maybe;
import io.reactivex.rxjava3.observers.TestObserver;
import java.util.List;
import java.util.function.Function;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class WebhookSignatureGeneratorPolicyTest {

  @Mock
  private HttpPlainExecutionContext plainContext;

  @Mock
  private HttpMessageExecutionContext messageContext;

  @Mock
  private io.gravitee.reporter.api.v4.metric.Metrics metrics;

  @Mock
  private TemplateEngine templateEngine;

  @Mock
  private HttpHeaders httpHeaders;

  @Mock
  private Message message;

  @Mock
  private Buffer buffer;

  private WebhookSignatureGeneratorPolicyConfiguration configuration;

  @BeforeEach
  void setUp() {
    configuration = new WebhookSignatureGeneratorPolicyConfiguration();
    configuration.setTargetSignatureHeader("X-HMAC-Signature");
    configuration.setAlgorithm("HmacSHA256");
    configuration.setSecret("mySecret");
  }

  @Test
  void shouldReturnCorrectPolicyId() {
    WebhookSignatureGeneratorPolicy policy =
      new WebhookSignatureGeneratorPolicy(configuration);
    assertThat(policy.id()).isEqualTo("webhook-signature-generator");
  }

  @Test
  void shouldGenerateSignatureOnResponse() {
    WebhookSignatureGeneratorPolicy policy =
      new WebhookSignatureGeneratorPolicy(configuration);

    String payload = "test payload";
    when(buffer.toString()).thenReturn(payload);
    doReturn(mockResponse(buffer)).when(plainContext).response();
    when(plainContext.getTemplateEngine()).thenReturn(templateEngine);
    when(templateEngine.getValue("mySecret", String.class))
      .thenReturn("mySecret");

    TestObserver<Void> testObserver = policy.onResponse(plainContext).test();

    testObserver.assertComplete();
    verify(httpHeaders)
      .set("X-HMAC-Signature", hmac(payload, "mySecret", "HmacSHA256"));
  }

  @Test
  void shouldGenerateDifferentSignaturesForDifferentPayloads() {
    WebhookSignatureGeneratorPolicy policy =
      new WebhookSignatureGeneratorPolicy(configuration);

    doReturn(mockResponse(buffer)).when(plainContext).response();
    when(plainContext.getTemplateEngine()).thenReturn(templateEngine);
    when(templateEngine.getValue("mySecret", String.class))
      .thenReturn("mySecret");

    ArgumentCaptor<String> signatureCaptor = ArgumentCaptor.forClass(
      String.class
    );

    when(buffer.toString()).thenReturn("payload1");
    policy.onResponse(plainContext).test().assertComplete();
    verify(httpHeaders).set(eq("X-HMAC-Signature"), signatureCaptor.capture());
    String signature1 = signatureCaptor.getValue();

    reset(httpHeaders);

    when(buffer.toString()).thenReturn("payload2");
    policy.onResponse(plainContext).test().assertComplete();
    verify(httpHeaders).set(eq("X-HMAC-Signature"), signatureCaptor.capture());
    String signature2 = signatureCaptor.getValue();

    assertThat(signature1).isNotEqualTo(signature2);
  }

  @Test
  void shouldUseDifferentAlgorithms() {
    doReturn(mockResponse(buffer)).when(plainContext).response();
    when(buffer.toString()).thenReturn("test payload");
    when(plainContext.getTemplateEngine()).thenReturn(templateEngine);
    when(templateEngine.getValue("mySecret", String.class))
      .thenReturn("mySecret");

    ArgumentCaptor<String> signatureCaptor = ArgumentCaptor.forClass(
      String.class
    );

    configuration.setAlgorithm("HmacSHA1");
    new WebhookSignatureGeneratorPolicy(configuration)
      .onResponse(plainContext)
      .test()
      .assertComplete();
    verify(httpHeaders).set(eq("X-HMAC-Signature"), signatureCaptor.capture());
    String signatureSHA1 = signatureCaptor.getValue();

    reset(httpHeaders);

    configuration.setAlgorithm("HmacSHA256");
    new WebhookSignatureGeneratorPolicy(configuration)
      .onResponse(plainContext)
      .test()
      .assertComplete();
    verify(httpHeaders).set(eq("X-HMAC-Signature"), signatureCaptor.capture());
    String signatureSHA256 = signatureCaptor.getValue();

    reset(httpHeaders);

    configuration.setAlgorithm("HmacSHA512");
    new WebhookSignatureGeneratorPolicy(configuration)
      .onResponse(plainContext)
      .test()
      .assertComplete();
    verify(httpHeaders).set(eq("X-HMAC-Signature"), signatureCaptor.capture());
    String signatureSHA512 = signatureCaptor.getValue();

    assertThat(signatureSHA1)
      .isEqualTo(hmac("test payload", "mySecret", "HmacSHA1"));
    assertThat(signatureSHA256)
      .isEqualTo(hmac("test payload", "mySecret", "HmacSHA256"));
    assertThat(signatureSHA512)
      .isEqualTo(hmac("test payload", "mySecret", "HmacSHA512"));
  }

  @Test
  void shouldGenerateSignatureWithAdditionalHeaders() {
    SchemeTypeConfiguration schemeType = new SchemeTypeConfiguration();
    schemeType.setEnabled(true);
    schemeType.setHeaders(List.of("X-Custom-Header"));
    schemeType.setHeadersDelimiter(".");
    configuration.setSchemeType(schemeType);

    WebhookSignatureGeneratorPolicy policy =
      new WebhookSignatureGeneratorPolicy(configuration);

    when(buffer.toString()).thenReturn("test payload");
    doReturn(mockResponse(buffer)).when(plainContext).response();
    when(plainContext.getTemplateEngine()).thenReturn(templateEngine);
    when(templateEngine.getValue("mySecret", String.class))
      .thenReturn("mySecret");
    when(httpHeaders.get("X-Custom-Header")).thenReturn("custom-value");

    TestObserver<Void> testObserver = policy.onResponse(plainContext).test();

    testObserver.assertComplete();
    verify(httpHeaders)
      .set(
        "X-HMAC-Signature",
        hmac("custom-value.test payload", "mySecret", "HmacSHA256")
      );
  }

  @Test
  void shouldFailWhenRequiredAdditionalHeaderIsMissing() {
    SchemeTypeConfiguration schemeType = new SchemeTypeConfiguration();
    schemeType.setEnabled(true);
    schemeType.setHeaders(List.of("X-Required-Header"));
    schemeType.setHeadersDelimiter(".");
    configuration.setSchemeType(schemeType);

    WebhookSignatureGeneratorPolicy policy =
      new WebhookSignatureGeneratorPolicy(configuration);

    when(buffer.toString()).thenReturn("test payload");
    doReturn(mockResponse(buffer)).when(plainContext).response();
    when(plainContext.getTemplateEngine()).thenReturn(templateEngine);
    when(templateEngine.getValue("mySecret", String.class))
      .thenReturn("mySecret");
    when(httpHeaders.get("X-Required-Header")).thenReturn(null);
    when(plainContext.metrics()).thenReturn(metrics);
    when(plainContext.interruptWith(any(ExecutionFailure.class)))
      .thenReturn(Completable.complete());

    TestObserver<Void> testObserver = policy.onResponse(plainContext).test();

    testObserver.assertComplete();
    ArgumentCaptor<ExecutionFailure> failureCaptor = ArgumentCaptor.forClass(
      ExecutionFailure.class
    );
    verify(plainContext).interruptWith(failureCaptor.capture());
    assertThat(failureCaptor.getValue().key())
      .isEqualTo("WEBHOOK_ADDITIONAL_HEADERS_NOT_VALID");
  }

  @Test
  void shouldFailWhenAdditionalHeadersEnabledButNoneConfigured() {
    SchemeTypeConfiguration schemeType = new SchemeTypeConfiguration();
    schemeType.setEnabled(true);
    schemeType.setHeaders(List.of());
    configuration.setSchemeType(schemeType);

    WebhookSignatureGeneratorPolicy policy =
      new WebhookSignatureGeneratorPolicy(configuration);

    when(buffer.toString()).thenReturn("test payload");
    doReturn(mockResponse(buffer)).when(plainContext).response();
    when(plainContext.getTemplateEngine()).thenReturn(templateEngine);
    when(templateEngine.getValue("mySecret", String.class))
      .thenReturn("mySecret");
    when(plainContext.metrics()).thenReturn(metrics);
    when(plainContext.interruptWith(any(ExecutionFailure.class)))
      .thenReturn(Completable.complete());

    TestObserver<Void> testObserver = policy.onResponse(plainContext).test();

    testObserver.assertComplete();
    ArgumentCaptor<ExecutionFailure> failureCaptor = ArgumentCaptor.forClass(
      ExecutionFailure.class
    );
    verify(plainContext).interruptWith(failureCaptor.capture());
    assertThat(failureCaptor.getValue().key())
      .isEqualTo("WEBHOOK_ADDITIONAL_HEADERS_NOT_VALID");
  }

  @Test
  void shouldGenerateSignatureWithTimestampAndSetHeader() {
    TimestampValidityConfiguration timestampValidity =
      new TimestampValidityConfiguration();
    timestampValidity.setEnabled(true);
    timestampValidity.setTargetTimestampHeader("X-HMAC-Timestamp");
    timestampValidity.setDelimiter(".");
    configuration.setTimestampValidity(timestampValidity);

    WebhookSignatureGeneratorPolicy policy =
      new WebhookSignatureGeneratorPolicy(configuration);

    when(buffer.toString()).thenReturn("test payload");
    doReturn(mockResponse(buffer)).when(plainContext).response();
    when(plainContext.getTemplateEngine()).thenReturn(templateEngine);
    when(templateEngine.getValue("mySecret", String.class))
      .thenReturn("mySecret");

    TestObserver<Void> testObserver = policy.onResponse(plainContext).test();

    testObserver.assertComplete();

    ArgumentCaptor<String> timestampCaptor = ArgumentCaptor.forClass(
      String.class
    );
    verify(httpHeaders).set(eq("X-HMAC-Timestamp"), timestampCaptor.capture());
    String timestamp = timestampCaptor.getValue();
    assertThat(timestamp).matches("\\d+");

    verify(httpHeaders)
      .set(
        "X-HMAC-Signature",
        hmac(timestamp + ".test payload", "mySecret", "HmacSHA256")
      );
  }

  @Test
  void shouldGenerateSignatureOnMessageResponse() {
    WebhookSignatureGeneratorPolicy policy =
      new WebhookSignatureGeneratorPolicy(configuration);

    when(message.content()).thenReturn(Buffer.buffer("message payload"));
    when(message.headers()).thenReturn(httpHeaders);

    HttpMessageResponse response = mockMessageResponse();
    when(messageContext.response()).thenReturn(response);
    when(messageContext.getTemplateEngine()).thenReturn(templateEngine);
    when(templateEngine.getValue("mySecret", String.class))
      .thenReturn("mySecret");

    ArgumentCaptor<Function<Message, Maybe<Message>>> onMessageCaptor =
      ArgumentCaptor.forClass(Function.class);

    policy.onMessageResponse(messageContext).test().assertComplete();

    verify(response).onMessage(onMessageCaptor.capture());
    onMessageCaptor.getValue().apply(message).test().assertComplete();

    verify(httpHeaders)
      .set(
        "X-HMAC-Signature",
        hmac("message payload", "mySecret", "HmacSHA256")
      );
  }

  @Test
  void shouldGenerateSignatureOnMessageResponseWithAdditionalHeaders() {
    SchemeTypeConfiguration schemeType = new SchemeTypeConfiguration();
    schemeType.setEnabled(true);
    schemeType.setHeaders(List.of("X-Custom-Header"));
    schemeType.setHeadersDelimiter(".");
    configuration.setSchemeType(schemeType);

    WebhookSignatureGeneratorPolicy policy =
      new WebhookSignatureGeneratorPolicy(configuration);

    when(message.content()).thenReturn(Buffer.buffer("message payload"));
    when(message.headers()).thenReturn(httpHeaders);
    when(httpHeaders.get("X-Custom-Header")).thenReturn("custom-value");

    HttpMessageResponse response = mockMessageResponse();
    when(messageContext.response()).thenReturn(response);
    when(messageContext.getTemplateEngine()).thenReturn(templateEngine);
    when(templateEngine.getValue("mySecret", String.class))
      .thenReturn("mySecret");

    ArgumentCaptor<Function<Message, Maybe<Message>>> onMessageCaptor =
      ArgumentCaptor.forClass(Function.class);

    policy.onMessageResponse(messageContext).test().assertComplete();

    verify(response).onMessage(onMessageCaptor.capture());
    onMessageCaptor.getValue().apply(message).test().assertComplete();

    verify(httpHeaders)
      .set(
        "X-HMAC-Signature",
        hmac("custom-value.message payload", "mySecret", "HmacSHA256")
      );
  }

  @Test
  void shouldGenerateSignatureOnMessageResponseWithTimestamp() {
    TimestampValidityConfiguration timestampValidity =
      new TimestampValidityConfiguration();
    timestampValidity.setEnabled(true);
    timestampValidity.setTargetTimestampHeader("X-HMAC-Timestamp");
    timestampValidity.setDelimiter(".");
    configuration.setTimestampValidity(timestampValidity);

    WebhookSignatureGeneratorPolicy policy =
      new WebhookSignatureGeneratorPolicy(configuration);

    when(message.content()).thenReturn(Buffer.buffer("message payload"));
    when(message.headers()).thenReturn(httpHeaders);

    HttpMessageResponse response = mockMessageResponse();
    when(messageContext.response()).thenReturn(response);
    when(messageContext.getTemplateEngine()).thenReturn(templateEngine);
    when(templateEngine.getValue("mySecret", String.class))
      .thenReturn("mySecret");

    ArgumentCaptor<Function<Message, Maybe<Message>>> onMessageCaptor =
      ArgumentCaptor.forClass(Function.class);

    policy.onMessageResponse(messageContext).test().assertComplete();

    verify(response).onMessage(onMessageCaptor.capture());
    onMessageCaptor.getValue().apply(message).test().assertComplete();

    ArgumentCaptor<String> timestampCaptor = ArgumentCaptor.forClass(
      String.class
    );
    verify(httpHeaders).set(eq("X-HMAC-Timestamp"), timestampCaptor.capture());
    String timestamp = timestampCaptor.getValue();
    assertThat(timestamp).matches("\\d+");

    verify(httpHeaders)
      .set(
        "X-HMAC-Signature",
        hmac(timestamp + ".message payload", "mySecret", "HmacSHA256")
      );
  }

  @Test
  void shouldFailOnMessageResponseWhenRequiredAdditionalHeaderIsMissing() {
    SchemeTypeConfiguration schemeType = new SchemeTypeConfiguration();
    schemeType.setEnabled(true);
    schemeType.setHeaders(List.of("X-Required-Header"));
    schemeType.setHeadersDelimiter(".");
    configuration.setSchemeType(schemeType);

    WebhookSignatureGeneratorPolicy policy =
      new WebhookSignatureGeneratorPolicy(configuration);

    when(message.content()).thenReturn(Buffer.buffer("message payload"));
    when(message.headers()).thenReturn(httpHeaders);
    when(httpHeaders.get("X-Required-Header")).thenReturn(null);

    HttpMessageResponse response = mockMessageResponse();
    when(messageContext.response()).thenReturn(response);
    when(messageContext.getTemplateEngine()).thenReturn(templateEngine);
    when(templateEngine.getValue("mySecret", String.class))
      .thenReturn("mySecret");
    when(messageContext.interruptMessageWith(any(ExecutionFailure.class)))
      .thenReturn(Maybe.empty());

    ArgumentCaptor<Function<Message, Maybe<Message>>> onMessageCaptor =
      ArgumentCaptor.forClass(Function.class);

    policy.onMessageResponse(messageContext).test().assertComplete();

    verify(response).onMessage(onMessageCaptor.capture());
    onMessageCaptor.getValue().apply(message).test().assertComplete();

    ArgumentCaptor<ExecutionFailure> failureCaptor = ArgumentCaptor.forClass(
      ExecutionFailure.class
    );
    verify(messageContext).interruptMessageWith(failureCaptor.capture());
    assertThat(failureCaptor.getValue().key())
      .isEqualTo("WEBHOOK_ADDITIONAL_HEADERS_NOT_VALID");
  }

  // Helper methods

  private static String hmac(String data, String secret, String algorithm) {
    try {
      Mac mac = Mac.getInstance(algorithm);
      mac.init(new SecretKeySpec(secret.getBytes("UTF-8"), algorithm));
      return java.util.Base64
        .getEncoder()
        .encodeToString(mac.doFinal(data.getBytes("UTF-8")));
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private HttpPlainResponse mockResponse(Buffer buffer) {
    HttpPlainResponse response = mock(HttpPlainResponse.class);
    doReturn(Maybe.just(buffer)).when(response).body();
    doReturn(httpHeaders).when(response).headers();
    return response;
  }

  private HttpMessageResponse mockMessageResponse() {
    HttpMessageResponse response = mock(HttpMessageResponse.class);
    doAnswer(invocation -> Completable.complete())
      .when(response)
      .onMessage(any());
    return response;
  }
}
