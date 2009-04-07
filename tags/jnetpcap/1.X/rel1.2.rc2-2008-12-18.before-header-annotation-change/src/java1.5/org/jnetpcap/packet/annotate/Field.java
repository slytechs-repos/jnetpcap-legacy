/**
 * Copyright (C) 2008 Sly Technologies, Inc. This library is free
 * software; you can redistribute it and/or modify it under the terms
 * of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version. This library is distributed in the hope
 * that it will be useful, but WITHOUT ANY WARRANTY; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE. See the GNU Lesser General Public License for more
 * details. You should have received a copy of the GNU Lesser General
 * Public License along with this library; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301 USA
 */
package org.jnetpcap.packet.annotate;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.jnetpcap.packet.format.JFormatter.Priority;

/**
 * Marks a method as header field that should be included in
 * <code>JFormatter</code> output. For accessing values out of the
 * protocol header, none of the accessor methods need to be marked in
 * anyway, but if you want the field to be included in output by the
 * formatter such as <code>TextFormatter</code> field has to be
 * marked.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Target(ElementType.METHOD)
@Documented
@Retention(RetentionPolicy.RUNTIME)
public @interface Field {
  
  public final static String EMPTY = "";
  
  public final static String DEFAULT_FORMAT = "%s";
  
  public final static int DEFAULT_LENGTH = 32;
  
  int offset() default -1;

  int length() default DEFAULT_LENGTH;

  String name() default EMPTY;
  
  String display() default EMPTY;

  String nicname() default EMPTY;

  String format() default DEFAULT_FORMAT;
  
  String units() default EMPTY;
  
  String description() default EMPTY;
  
  String parent() default EMPTY;

  Priority priority() default Priority.MEDIUM;

}
