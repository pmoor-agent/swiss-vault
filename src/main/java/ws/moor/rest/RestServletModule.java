/*
 * Copyright 2012 Patrick Moor <patrick@moor.ws>
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

import com.google.common.base.Function;
import com.google.common.base.Predicate;
import com.google.common.collect.*;
import com.google.inject.AbstractModule;
import com.google.inject.Key;
import com.google.inject.Provider;
import com.google.inject.servlet.RequestScoped;
import com.google.inject.servlet.ServletModule;
import ws.moor.rest.annotations.*;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.lang.annotation.Annotation;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public abstract class RestServletModule extends AbstractModule {

  private static final Pattern PARAMETER_PATTERN = Pattern.compile("\\{([^\\}]+)\\}");

  private final String pattern;
  private final List<ActionMatcher> matchers;
  private final List<FilterMatcher> filters;
  
  public RestServletModule(String pattern) {
    this.pattern = pattern;
    this.matchers = Lists.newArrayList();
    this.filters = Lists.newArrayList();
  }
  
  @Override
  protected final void configure() {
    configureActions();

    for (ActionMatcher matcher : matchers) {
      matcher.pickFilters(filters);
      bind(matcher.actionClass).in(RequestScoped.class);
    }
    for (FilterMatcher filter : filters) {
      bind(filter.filterClass).in(RequestScoped.class);
    }
    install(new ServletModule() {
      @Override protected void configureServlets() {
        serve(pattern).with(new RestServlet(matchers, binder().getProvider(RestCallInvocator.class)));
      }
    });
  }

  abstract protected void configureActions();

  protected void addAction(Class<? extends RestAction> action) {
    matchers.add(getActionMatcher(action));
  }

  protected void addFilter(Class<? extends RestFilter> filter) {
    filters.add(getFilterMatcher(filter));
  }

  FilterMatcher getFilterMatcher(Class<? extends RestFilter> filter) {
    Set<Annotation> annotations = Sets.newHashSet(filter.getAnnotations());
    Iterable<Annotation> filterAnnotations = Iterables.filter(
        annotations, new Predicate<Annotation>() {
      @Override public boolean apply(Annotation input) {
        Class<? extends Annotation> type = input.annotationType();
        return type.getAnnotation(FilterAnnotation.class) != null;
      }
    });
    Iterable<Class<? extends Annotation>> types = Iterables.transform(
        filterAnnotations, new Function<Annotation, Class<? extends Annotation>>() {
      @Override public Class<? extends Annotation> apply(Annotation input) {
        return input.annotationType();
      }
    });
    return new FilterMatcher(filter, types);
  }

  private ActionMatcher getActionMatcher(Class<? extends RestAction> actionClass) {
    Get getAnnotation = actionClass.getAnnotation(Get.class);
    if (getAnnotation != null) {
      return new ActionMatcher(Verb.GET, getAnnotation.path(), actionClass);
    }

    Post postAnnotation = actionClass.getAnnotation(Post.class);
    if (postAnnotation != null) {
      return new ActionMatcher(Verb.POST, postAnnotation.path(), actionClass);
    }

    Put putAnnotation = actionClass.getAnnotation(Put.class);
    if (putAnnotation != null) {
      return new ActionMatcher(Verb.PUT, putAnnotation.path(), actionClass);
    }

    Delete deleteAnnotation = actionClass.getAnnotation(Delete.class);
    if (deleteAnnotation != null) {
      return new ActionMatcher(Verb.DELETE, deleteAnnotation.path(), actionClass);
    }

    throw new IllegalArgumentException("no annotation found on " + actionClass.getName());
  }

  private static class RestServlet extends HttpServlet {

    private static final Logger logger = Logger.getLogger(RestServlet.class.getName());

    private final List<ActionMatcher> matchers;
    private final Provider<RestCallInvocator> invocatorProvider;

    RestServlet(List<ActionMatcher> matchers, Provider<RestCallInvocator> invocatorProvider) {
      this.matchers = matchers;
      this.invocatorProvider = invocatorProvider;
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
      doVerb(Verb.GET, req, resp);
    }
  
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
      doVerb(Verb.POST, req, resp);
    }
  
    @Override
    protected void doPut(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
      doVerb(Verb.PUT, req, resp);
    }
  
    @Override
    protected void doDelete(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
      doVerb(Verb.DELETE, req, resp);
    }
  
    private void doVerb(Verb verb, HttpServletRequest req, HttpServletResponse resp) throws IOException {
      for (ActionMatcher matcher : matchers) {
        RestCallContext context = matcher.match(verb, req.getPathInfo());
        if (context != null) {
          req.setAttribute(
              Key.get(RestCallContext.class).toString(), context);
          try {
            invocatorProvider.get().invoke();
          } catch (RuntimeException e) {
            logger.log(Level.WARNING, "low-level error - should not happen", e);
            throw e;
          }
          return;
        }
      }
      resp.sendError(HttpServletResponse.SC_NOT_FOUND);
    }
  }

  private static class ActionMatcher {

    private final List<String> parameterOrder;
    private final Pattern pathPattern;
    private final Verb verb;
    private final Class<? extends RestAction> actionClass;
    private List<Class<? extends RestFilter>> filterClasses;

    public ActionMatcher(Verb verb, String path, Class<? extends RestAction> actionClass) {
      this.parameterOrder = Lists.newArrayList();
      
      Matcher matcher = PARAMETER_PATTERN.matcher(path);
      StringBuffer patternBuffer = new StringBuffer();
      while (matcher.find()) {
        parameterOrder.add(matcher.group(1));
        matcher.appendReplacement(patternBuffer, "(\\\\w+)");
      }
      matcher.appendTail(patternBuffer);

      this.pathPattern = Pattern.compile(patternBuffer.toString());
      this.verb = verb;
      this.actionClass = actionClass;
    }

    public RestCallContext match(Verb verb, String pathInfo) {
      if (verb != this.verb) {
        return null;
      }
      Matcher matcher = pathPattern.matcher(pathInfo);
      if (matcher.matches()) {
        ImmutableMap.Builder<String, String> builder = ImmutableMap.builder();
        for (int i = 0; i < parameterOrder.size(); i++) {
          builder.put(parameterOrder.get(i), matcher.group(i + 1));
        }
        return new RestCallContext(verb, actionClass, filterClasses, builder.build());
      } else {
        return null;
      }
    }

    public void pickFilters(List<FilterMatcher> filters) {
      filterClasses = ImmutableList.copyOf(
          Iterables.transform(
            Iterables.filter(
                filters,
                new Predicate<FilterMatcher>() {
                  @Override public boolean apply(FilterMatcher input) {
                    return input.applies(actionClass);
                  }
                }),
            new Function<FilterMatcher, Class<? extends RestFilter>>() {
              @Override public Class<? extends RestFilter> apply(FilterMatcher input) {
                return input.filterClass;
              }
            }));
    }
  }
  
  static class FilterMatcher {

    private final Class<? extends RestFilter> filterClass;
    private final Set<Class<? extends Annotation>> annotationTypes;

    FilterMatcher(Class<? extends RestFilter> filterClass, Iterable<Class<? extends Annotation>> annotationTypes) {
      this.filterClass = filterClass;
      this.annotationTypes = ImmutableSet.copyOf(annotationTypes);
    }

    boolean applies(Class<? extends RestAction> actionClass) {
      for (Class<? extends Annotation> annotationType : annotationTypes) {
        if (!actionClass.isAnnotationPresent(annotationType)) {
          return false;
        }
      }
      return true;
    }
  }
}
