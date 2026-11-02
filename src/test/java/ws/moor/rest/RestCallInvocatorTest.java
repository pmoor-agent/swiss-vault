/*
 * Copyright 2026 Patrick Moor <patrick@moor.ws>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ws.moor.rest;

import com.google.appengine.api.datastore.EntityNotFoundException;
import com.google.appengine.api.datastore.Transaction;
import com.google.common.collect.ImmutableList;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonPrimitive;
import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.inject.Injector;
import com.google.inject.Key;
import com.google.inject.Module;
import com.google.inject.Provider;
import com.google.inject.Provides;
import com.google.inject.ProvisionException;
import org.junit.Test;
import ws.moor.rest.annotations.Execute;
import ws.moor.rest.annotations.PreFilter;
import ws.moor.swissvault.domain.KeyNotFoundException;
import ws.moor.swissvault.domain.PermissionDeniedException;
import ws.moor.swissvault.rest.filters.TransactionFilter;

import javax.servlet.ServletOutputStream;
import javax.servlet.WriteListener;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Future;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

public class RestCallInvocatorTest {

  // --- Fake Classes ---

  private static class FakeTransaction implements Transaction {
    boolean active = true;
    boolean rolledBack = false;
    boolean committed = false;

    @Override
    public void commit() {
      if (!active) throw new IllegalStateException("transaction not active");
      active = false;
      committed = true;
    }

    @Override
    public Future<Void> commitAsync() {
      return null;
    }

    @Override
    public void rollback() {
      if (!active) throw new IllegalStateException("transaction not active");
      active = false;
      rolledBack = true;
    }

    @Override
    public Future<Void> rollbackAsync() {
      return null;
    }

    @Override
    public String getId() {
      return "fake-tx";
    }

    @Override
    public String getApp() {
      return "fake-app";
    }

    @Override
    public boolean isActive() {
      return active;
    }
  }

  private static class FakeResponse {
    int status = 0;
    Integer errorCode = null;
    String errorMessage = null;
    String contentType = null;
    final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

    HttpServletResponse asHttpServletResponse() {
      return (HttpServletResponse) Proxy.newProxyInstance(
          HttpServletResponse.class.getClassLoader(),
          new Class<?>[]{HttpServletResponse.class},
          (proxy, method, args) -> {
            String name = method.getName();
            if ("setStatus".equals(name)) {
              status = (Integer) args[0];
              return null;
            } else if ("getStatus".equals(name)) {
              return status;
            } else if ("setContentType".equals(name)) {
              contentType = (String) args[0];
              return null;
            } else if ("getContentType".equals(name)) {
              return contentType;
            } else if ("getOutputStream".equals(name)) {
              return new ServletOutputStream() {
                @Override
                public boolean isReady() {
                  return true;
                }

                @Override
                public void setWriteListener(WriteListener writeListener) {}

                @Override
                public void write(int b) {
                  outputStream.write(b);
                }

                @Override
                public void write(byte[] b, int off, int len) {
                  outputStream.write(b, off, len);
                }
              };
            } else if ("sendError".equals(name)) {
              errorCode = (Integer) args[0];
              if (args.length > 1) {
                errorMessage = (String) args[1];
              }
              return null;
            }
            return null;
          });
    }

    String getBodyAsString() {
      return outputStream.toString(StandardCharsets.UTF_8);
    }
  }

  private static class FakeRequest {
    final Map<String, Object> attributes = new HashMap<>();

    HttpServletRequest asHttpServletRequest() {
      return (HttpServletRequest) Proxy.newProxyInstance(
          HttpServletRequest.class.getClassLoader(),
          new Class<?>[]{HttpServletRequest.class},
          (proxy, method, args) -> {
            String name = method.getName();
            if ("getAttribute".equals(name)) {
              return attributes.get(args[0]);
            } else if ("setAttribute".equals(name)) {
              attributes.put((String) args[0], args[1]);
              return null;
            }
            return null;
          });
    }
  }

  // --- Actions ---

  public static class CommittingAction implements RestAction {
    @Execute
    public JsonObject execute(HttpServletRequest request) {
      Transaction tx = (Transaction) request.getAttribute(Key.get(Transaction.class).toString());
      tx.commit();
      JsonObject obj = new JsonObject();
      obj.addProperty("status", "ok");
      return obj;
    }
  }

  public static class ThrowingKeyNotFoundAction implements RestAction {
    @Execute
    public void execute() {
      throw new KeyNotFoundException();
    }
  }

  public static class ThrowingEntityNotFoundAction implements RestAction {
    @Execute
    public void execute() throws EntityNotFoundException {
      throw new EntityNotFoundException(null);
    }
  }

  public static class ThrowingPermissionDeniedAction implements RestAction {
    @Execute
    public void execute() throws PermissionDeniedException {
      throw new PermissionDeniedException("action denied");
    }
  }

  public static class ThrowingIllegalArgumentAction implements RestAction {
    @Execute
    public void execute() {
      throw new IllegalArgumentException("invalid argument");
    }
  }

  public static class ThrowingJsonParseAction implements RestAction {
    @Execute
    public void execute() {
      throw new JsonParseException("malformed json");
    }
  }

  public static class ThrowingIllegalStateAction implements RestAction {
    @Execute
    public void execute() {
      throw new IllegalStateException("illegal state in action");
    }
  }

  public static class ThrowingNullPointerAction implements RestAction {
    @Execute
    public void execute() {
      throw new NullPointerException("unhandled null");
    }
  }

  public static class ThrowingAssertionErrorAction implements RestAction {
    @Execute
    public void execute() {
      throw new AssertionError("assertion failed");
    }
  }

  public static class ThrowingCheckedExceptionAction implements RestAction {
    @Execute
    public void execute() throws Exception {
      throw new Exception("checked exception");
    }
  }

  public static class ActionReturningJsonObject implements RestAction {
    @Execute
    public JsonObject execute() {
      JsonObject obj = new JsonObject();
      obj.addProperty("greeting", "Grüezi Zürich 🔑");
      return obj;
    }
  }

  public static class ActionReturningJsonArray implements RestAction {
    @Execute
    public JsonArray execute() {
      JsonArray array = new JsonArray();
      array.add(new JsonPrimitive("item1"));
      array.add(new JsonPrimitive("Schlüssel 🔑"));
      return array;
    }
  }

  public static class ActionReturningNull implements RestAction {
    @Execute
    public Object execute() {
      return null;
    }
  }

  public static class ActionReturningUnknownType implements RestAction {
    @Execute
    public String execute() {
      return "plain string";
    }
  }

  public static class ActionWithInjectedParam implements RestAction {
    @Execute
    public void execute(CustomParam param) {}
  }

  private static class CustomParam {}

  // --- Filters ---

  public static class ThrowingPreFilter implements RestFilter {
    @PreFilter
    public void pre() throws PermissionDeniedException {
      throw new PermissionDeniedException("pre-filter auth failed");
    }
  }

  // --- Helper Methods ---

  private RestCallInvocator createInvocator(
      Class<? extends RestAction> actionClass,
      List<Class<? extends RestFilter>> filters,
      FakeRequest fakeRequest,
      FakeResponse fakeResponse) {
    return createInvocator(actionClass, filters, fakeRequest, fakeResponse, null);
  }

  private RestCallInvocator createInvocator(
      Class<? extends RestAction> actionClass,
      List<Class<? extends RestFilter>> filters,
      FakeRequest fakeRequest,
      FakeResponse fakeResponse,
      Module extraModule) {
    Module baseModule = new AbstractModule() {
      @Override
      protected void configure() {
        bind(HttpServletRequest.class).toInstance(fakeRequest.asHttpServletRequest());
        bind(HttpServletResponse.class).toInstance(fakeResponse.asHttpServletResponse());
        bind(actionClass);
      }
    };
    Injector injector = extraModule != null
        ? Guice.createInjector(baseModule, extraModule)
        : Guice.createInjector(baseModule);
    Provider<RestAction> actionProvider = () -> injector.getInstance(actionClass);
    return new RestCallInvocator(
        actionClass,
        actionProvider,
        injector,
        fakeResponse.asHttpServletResponse(),
        filters);
  }

  // --- Tests ---

  @Test
  public void testTransactionRolledBackWhenExecuteThrowsKeyNotFoundException() {
    FakeRequest request = new FakeRequest();
    FakeResponse response = new FakeResponse();
    FakeTransaction transaction = new FakeTransaction();
    request.attributes.put(Key.get(Transaction.class).toString(), transaction);

    RestCallInvocator invocator = createInvocator(
        ThrowingKeyNotFoundAction.class,
        ImmutableList.of(TransactionFilter.class),
        request,
        response);

    invocator.invoke();

    assertThat(transaction.rolledBack).isTrue();
    assertThat(transaction.isActive()).isFalse();
    assertThat(response.errorCode).isEqualTo(HttpServletResponse.SC_NOT_FOUND);
    assertThat(response.errorMessage).isNull();
  }

  @Test
  public void testTransactionRolledBackWhenPreFilterThrows() {
    FakeRequest request = new FakeRequest();
    FakeResponse response = new FakeResponse();
    FakeTransaction transaction = new FakeTransaction();
    request.attributes.put(Key.get(Transaction.class).toString(), transaction);

    RestCallInvocator invocator = createInvocator(
        ActionReturningNull.class,
        ImmutableList.of(ThrowingPreFilter.class, TransactionFilter.class),
        request,
        response);

    invocator.invoke();

    assertThat(transaction.rolledBack).isTrue();
    assertThat(transaction.isActive()).isFalse();
    assertThat(response.errorCode).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
    assertThat(response.errorMessage).isEqualTo("pre-filter auth failed");
  }

  @Test
  public void testSuccessfulActionCommitsAndPostFilterDoesNotRollback() {
    FakeRequest request = new FakeRequest();
    FakeResponse response = new FakeResponse();
    FakeTransaction transaction = new FakeTransaction();
    request.attributes.put(Key.get(Transaction.class).toString(), transaction);

    RestCallInvocator invocator = createInvocator(
        CommittingAction.class,
        ImmutableList.of(TransactionFilter.class),
        request,
        response);

    invocator.invoke();

    assertThat(transaction.committed).isTrue();
    assertThat(transaction.rolledBack).isFalse();
    assertThat(response.status).isEqualTo(HttpServletResponse.SC_OK);
  }

  @Test
  public void testPermissionDeniedExceptionReturns403() {
    FakeRequest request = new FakeRequest();
    FakeResponse response = new FakeResponse();

    RestCallInvocator invocator = createInvocator(
        ThrowingPermissionDeniedAction.class,
        ImmutableList.of(),
        request,
        response);

    invocator.invoke();

    assertThat(response.errorCode).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
    assertThat(response.errorMessage).isEqualTo("action denied");
  }

  @Test
  public void testEntityNotFoundExceptionReturns404() {
    FakeRequest request = new FakeRequest();
    FakeResponse response = new FakeResponse();

    RestCallInvocator invocator = createInvocator(
        ThrowingEntityNotFoundAction.class,
        ImmutableList.of(),
        request,
        response);

    invocator.invoke();

    assertThat(response.errorCode).isEqualTo(HttpServletResponse.SC_NOT_FOUND);
  }

  @Test
  public void testIllegalArgumentExceptionReturns400() {
    FakeRequest request = new FakeRequest();
    FakeResponse response = new FakeResponse();

    RestCallInvocator invocator = createInvocator(
        ThrowingIllegalArgumentAction.class,
        ImmutableList.of(),
        request,
        response);

    invocator.invoke();

    assertThat(response.errorCode).isEqualTo(HttpServletResponse.SC_BAD_REQUEST);
    assertThat(response.errorMessage).isEqualTo("invalid argument");
  }

  @Test
  public void testJsonParseExceptionReturns400() {
    FakeRequest request = new FakeRequest();
    FakeResponse response = new FakeResponse();

    RestCallInvocator invocator = createInvocator(
        ThrowingJsonParseAction.class,
        ImmutableList.of(),
        request,
        response);

    invocator.invoke();

    assertThat(response.errorCode).isEqualTo(HttpServletResponse.SC_BAD_REQUEST);
    assertThat(response.errorMessage).isEqualTo("malformed json");
  }

  @Test
  public void testIllegalStateExceptionReturns400() {
    FakeRequest request = new FakeRequest();
    FakeResponse response = new FakeResponse();

    RestCallInvocator invocator = createInvocator(
        ThrowingIllegalStateAction.class,
        ImmutableList.of(),
        request,
        response);

    invocator.invoke();

    assertThat(response.errorCode).isEqualTo(HttpServletResponse.SC_BAD_REQUEST);
    assertThat(response.errorMessage).isEqualTo("illegal state in action");
  }

  @Test
  public void testProvisionExceptionWrappingJsonParseExceptionReturns400() {
    FakeRequest request = new FakeRequest();
    FakeResponse response = new FakeResponse();

    Module failingProviderModule = new AbstractModule() {
      @Provides
      CustomParam provideCustomParam() {
        throw new JsonParseException("provider failed to parse JSON");
      }
    };

    RestCallInvocator invocator = createInvocator(
        ActionWithInjectedParam.class,
        ImmutableList.of(),
        request,
        response,
        failingProviderModule);

    invocator.invoke();

    assertThat(response.errorCode).isEqualTo(HttpServletResponse.SC_BAD_REQUEST);
    assertThat(response.errorMessage).isEqualTo("provider failed to parse JSON");
  }

  @Test
  public void testProvisionExceptionWrappingIllegalArgumentExceptionReturns400() {
    FakeRequest request = new FakeRequest();
    FakeResponse response = new FakeResponse();

    Module failingProviderModule = new AbstractModule() {
      @Provides
      CustomParam provideCustomParam() {
        throw new IllegalArgumentException("invalid provider argument");
      }
    };

    RestCallInvocator invocator = createInvocator(
        ActionWithInjectedParam.class,
        ImmutableList.of(),
        request,
        response,
        failingProviderModule);

    invocator.invoke();

    assertThat(response.errorCode).isEqualTo(HttpServletResponse.SC_BAD_REQUEST);
    assertThat(response.errorMessage).isEqualTo("invalid provider argument");
  }

  @Test
  public void testNestedProvisionAndInvocationTargetExceptionUnwrapping() {
    FakeRequest request = new FakeRequest();
    FakeResponse response = new FakeResponse();

    Module failingProviderModule = new AbstractModule() {
      @Provides
      CustomParam provideCustomParam() {
        // Nested: ProvisionException wrapping InvocationTargetException wrapping IllegalArgumentException
        Throwable ite = new InvocationTargetException(new IllegalArgumentException("deeply nested argument error"));
        throw new ProvisionException("outer provision exception", ite);
      }
    };

    RestCallInvocator invocator = createInvocator(
        ActionWithInjectedParam.class,
        ImmutableList.of(),
        request,
        response,
        failingProviderModule);

    invocator.invoke();

    assertThat(response.errorCode).isEqualTo(HttpServletResponse.SC_BAD_REQUEST);
    assertThat(response.errorMessage).isEqualTo("deeply nested argument error");
  }

  @Test
  public void testUnhandledRuntimeExceptionIsRethrownAndRollsBackTransaction() {
    FakeRequest request = new FakeRequest();
    FakeResponse response = new FakeResponse();
    FakeTransaction transaction = new FakeTransaction();
    request.attributes.put(Key.get(Transaction.class).toString(), transaction);

    RestCallInvocator invocator = createInvocator(
        ThrowingNullPointerAction.class,
        ImmutableList.of(TransactionFilter.class),
        request,
        response);

    NullPointerException thrown = assertThrows(NullPointerException.class, invocator::invoke);
    assertThat(thrown).hasMessageThat().isEqualTo("unhandled null");
    assertThat(transaction.rolledBack).isTrue();
  }

  @Test
  public void testUnhandledErrorIsRethrown() {
    FakeRequest request = new FakeRequest();
    FakeResponse response = new FakeResponse();

    RestCallInvocator invocator = createInvocator(
        ThrowingAssertionErrorAction.class,
        ImmutableList.of(),
        request,
        response);

    assertThrows(AssertionError.class, invocator::invoke);
  }

  @Test
  public void testUnhandledCheckedExceptionIsWrappedInRuntimeException() {
    FakeRequest request = new FakeRequest();
    FakeResponse response = new FakeResponse();

    RestCallInvocator invocator = createInvocator(
        ThrowingCheckedExceptionAction.class,
        ImmutableList.of(),
        request,
        response);

    RuntimeException thrown = assertThrows(RuntimeException.class, invocator::invoke);
    assertThat(thrown.getCause()).isInstanceOf(Exception.class);
    assertThat(thrown.getCause()).hasMessageThat().isEqualTo("checked exception");
  }

  @Test
  public void testJsonObjectResponseSetsContentTypeAndUtf8Bytes() {
    FakeRequest request = new FakeRequest();
    FakeResponse response = new FakeResponse();

    RestCallInvocator invocator = createInvocator(
        ActionReturningJsonObject.class,
        ImmutableList.of(),
        request,
        response);

    invocator.invoke();

    assertThat(response.status).isEqualTo(HttpServletResponse.SC_OK);
    assertThat(response.contentType).isEqualTo("application/json; charset=utf-8");
    assertThat(response.getBodyAsString()).isEqualTo("{\"greeting\":\"Grüezi Zürich 🔑\"}");
  }

  @Test
  public void testJsonArrayResponseSetsContentTypeAndUtf8Bytes() {
    FakeRequest request = new FakeRequest();
    FakeResponse response = new FakeResponse();

    RestCallInvocator invocator = createInvocator(
        ActionReturningJsonArray.class,
        ImmutableList.of(),
        request,
        response);

    invocator.invoke();

    assertThat(response.status).isEqualTo(HttpServletResponse.SC_OK);
    assertThat(response.contentType).isEqualTo("application/json; charset=utf-8");
    assertThat(response.getBodyAsString()).isEqualTo("[\"item1\",\"Schlüssel 🔑\"]");
  }

  @Test
  public void testNullResultReturns204NoContent() {
    FakeRequest request = new FakeRequest();
    FakeResponse response = new FakeResponse();

    RestCallInvocator invocator = createInvocator(
        ActionReturningNull.class,
        ImmutableList.of(),
        request,
        response);

    invocator.invoke();

    assertThat(response.status).isEqualTo(HttpServletResponse.SC_NO_CONTENT);
    assertThat(response.outputStream.toByteArray()).isEmpty();
  }

  @Test
  public void testUnknownReturnTypeThrowsRuntimeException() {
    FakeRequest request = new FakeRequest();
    FakeResponse response = new FakeResponse();

    RestCallInvocator invocator = createInvocator(
        ActionReturningUnknownType.class,
        ImmutableList.of(),
        request,
        response);

    RuntimeException thrown = assertThrows(RuntimeException.class, invocator::invoke);
    assertThat(thrown).hasMessageThat().contains("unknown response type");
  }
}
