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

import com.google.common.collect.ImmutableList;
import org.junit.Test;
import ws.moor.rest.RestServletModule.FilterMatcher;
import ws.moor.rest.annotations.FilterAnnotation;
import ws.moor.rest.annotations.Get;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import static com.google.common.truth.Truth.assertThat;

public class RestServletModuleTest {

  @Retention(RetentionPolicy.RUNTIME)
  @Target(ElementType.TYPE)
  @FilterAnnotation
  private @interface AnnotationA {}

  @Retention(RetentionPolicy.RUNTIME)
  @Target(ElementType.TYPE)
  @FilterAnnotation
  private @interface AnnotationB {}

  @Retention(RetentionPolicy.RUNTIME)
  @Target(ElementType.TYPE)
  private @interface NonFilterAnnotation {}

  private static class DummyFilter implements RestFilter {}

  @AnnotationA
  private static class FilterWithAnnotationA implements RestFilter {}

  @AnnotationA
  @AnnotationB
  @NonFilterAnnotation
  private static class FilterWithABAndNonFilterAnnotation implements RestFilter {}

  @Get(path = "/unannotated")
  private static class UnannotatedAction implements RestAction {}

  @AnnotationA
  @Get(path = "/annotated-a")
  private static class AnnotatedWithAAction implements RestAction {}

  @AnnotationB
  @Get(path = "/annotated-b")
  private static class AnnotatedWithBAction implements RestAction {}

  @AnnotationA
  @AnnotationB
  @Get(path = "/annotated-ab")
  private static class AnnotatedWithABAction implements RestAction {}

  @Test
  public void testFilterMatcherWithNoAnnotationsAppliesToAllActions() {
    FilterMatcher matcher = new FilterMatcher(DummyFilter.class, ImmutableList.of());
    assertThat(matcher.applies(UnannotatedAction.class)).isTrue();
    assertThat(matcher.applies(AnnotatedWithAAction.class)).isTrue();
    assertThat(matcher.applies(AnnotatedWithBAction.class)).isTrue();
    assertThat(matcher.applies(AnnotatedWithABAction.class)).isTrue();
  }

  @Test
  public void testFilterMatcherWithSingleAnnotation() {
    FilterMatcher matcher = new FilterMatcher(DummyFilter.class, ImmutableList.of(AnnotationA.class));
    assertThat(matcher.applies(UnannotatedAction.class)).isFalse();
    assertThat(matcher.applies(AnnotatedWithAAction.class)).isTrue();
    assertThat(matcher.applies(AnnotatedWithBAction.class)).isFalse();
    assertThat(matcher.applies(AnnotatedWithABAction.class)).isTrue();
  }

  @Test
  public void testFilterMatcherWithMultipleAnnotationsRequiresAll() {
    FilterMatcher matcher = new FilterMatcher(
        DummyFilter.class, ImmutableList.of(AnnotationA.class, AnnotationB.class));
    assertThat(matcher.applies(UnannotatedAction.class)).isFalse();
    assertThat(matcher.applies(AnnotatedWithAAction.class)).isFalse();
    assertThat(matcher.applies(AnnotatedWithBAction.class)).isFalse();
    assertThat(matcher.applies(AnnotatedWithABAction.class)).isTrue();
  }

  @Test
  public void testRestServletModuleFilterMatcherExtraction() {
    TestModule module = new TestModule("/api/*");

    FilterMatcher globalMatcher = module.getFilterMatcher(DummyFilter.class);
    assertThat(globalMatcher.applies(UnannotatedAction.class)).isTrue();
    assertThat(globalMatcher.applies(AnnotatedWithAAction.class)).isTrue();

    FilterMatcher aMatcher = module.getFilterMatcher(FilterWithAnnotationA.class);
    assertThat(aMatcher.applies(UnannotatedAction.class)).isFalse();
    assertThat(aMatcher.applies(AnnotatedWithAAction.class)).isTrue();
    assertThat(aMatcher.applies(AnnotatedWithBAction.class)).isFalse();
    assertThat(aMatcher.applies(AnnotatedWithABAction.class)).isTrue();

    FilterMatcher abMatcher = module.getFilterMatcher(FilterWithABAndNonFilterAnnotation.class);
    assertThat(abMatcher.applies(UnannotatedAction.class)).isFalse();
    assertThat(abMatcher.applies(AnnotatedWithAAction.class)).isFalse();
    assertThat(abMatcher.applies(AnnotatedWithBAction.class)).isFalse();
    assertThat(abMatcher.applies(AnnotatedWithABAction.class)).isTrue();
  }

  private static class TestModule extends RestServletModule {
    TestModule(String pattern) {
      super(pattern);
    }

    @Override
    protected void configureActions() {}
  }
}
