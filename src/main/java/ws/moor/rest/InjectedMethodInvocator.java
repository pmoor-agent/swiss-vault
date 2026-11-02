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

import com.google.inject.BindingAnnotation;
import com.google.inject.Injector;
import com.google.inject.Key;

import java.lang.annotation.Annotation;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Type;

import static com.google.common.base.Preconditions.checkArgument;

class InjectedMethodInvocator {
  
  private final Method method;
  private final Key[] keys;

  InjectedMethodInvocator(Method method) {
    this.method = method;
    this.keys = calculateGuiceKeys(method);
  }

  public Object invoke(Injector injector, Object target) throws InvocationTargetException, IllegalAccessException {
    Object[] arguments = new Object[keys.length];
    for (int i = 0; i < keys.length; i++) {
      arguments[i] = injector.getInstance(keys[i]);
    }
    return method.invoke(target, arguments);
  }

  private Key[] calculateGuiceKeys(Method method) {
    Type[] parameterTypes = method.getGenericParameterTypes();
    Annotation[][] parameterAnnotations = method.getParameterAnnotations();
    checkArgument(parameterTypes.length == parameterAnnotations.length);
    Key[] keys = new Key[parameterTypes.length];
    for (int i = 0; i < parameterTypes.length; i++) {
      Type type = parameterTypes[i];
      Annotation[] annotations = parameterAnnotations[i];
      Annotation bindingAnnotation = getBindingAnnotation(annotations);
      if (bindingAnnotation != null) {
        keys[i] = Key.get(type, bindingAnnotation);
      } else {
        keys[i] = Key.get(type);
      }
    }
    return keys;
  }
  
  private Annotation getBindingAnnotation(Annotation[] annotations) {
    for (Annotation annotation : annotations) {
      if (annotation.annotationType().getAnnotation(BindingAnnotation.class) != null) {
        return annotation;
      }
    }
    return null;
  }
}
