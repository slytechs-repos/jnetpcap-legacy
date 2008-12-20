/**
 * Copyright (C) 2008 Sly Technologies, Inc. This library is free software; you
 * can redistribute it and/or modify it under the terms of the GNU Lesser
 * General Public License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version. This
 * library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details. You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */
package org.jnetpcap.packet.annotate;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.jnetpcap.packet.format.JFormatter.Priority;

/**
 * Defines a header field's getter method. Any method annotated with
 * <code>Field</code> annotation will be included in <code>JFormatter</code>
 * output. The field annotation allows a number of constant properties about the
 * field to be declared. By default, the method's name becomes the field name as
 * well.
 * <p>
 * The <code>Field</code> annotation provides a way to set any of the field's
 * properties statically. The value set using this annotation will be set
 * permanently as a constant for that property. If the property is ommited, its
 * default value will be used or if a instance method is defined that is marked
 * with <code>FieldRuntime</code> annotation, then than method will be used at
 * runtime to obtain the value for the property it generating values for. For
 * example, the <code>display</code> field property which is used as text to
 * display whenever a textual name for the field is needed, can be set
 * statically using this annotation:
 * 
 * <pre>
 * &#064;Field(display = &quot;more descriptive name of the field&quot;)
 * public int fieldA() {
 * 	return 0;
 * }
 * </pre>
 * 
 * or the same property can be generated dynamically at runtime by ommiting the
 * the annotation parameter "display" in this annotation and supplying a
 * separate instance method which generates the value:
 * 
 * <pre>
 * &#064;FieldRuntime(FieldFunction.DISPLAY)
 * public String fieldADisplay() {
 * 	return (fieldA() == 0) ? &quot;FIELD_A&quot; : &quot;fieldA&quot;;
 * }
 * </pre>
 * 
 * Both Field.display and the runtime method can not be set at the same time.
 * Again by default the name of the field is used as display of the field's
 * name.
 * </p>
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Target(ElementType.METHOD)
@Documented
@Retention(RetentionPolicy.RUNTIME)
public @interface Field {

	/**
	 * An empty string
	 */
	public final static String EMPTY = "";

	/**
	 * Default formatting string for field's value
	 */
	public final static String DEFAULT_FORMAT = "%s";

	/**
	 * Static offset of this field into the header in bits. This parameter
	 * specifies in bits, the exact offset of the annotated field within the
	 * current header. The value is constant. If offset of the field is not
	 * constant but varies and can only be determined at runtime, then this
	 * parameter should not be used. Instead use a method and mark it with
	 * <code>@FieldRuntime(FieldFunction.OFFSET)</code> annotation.
	 * @return offset into the header in bits
	 */
	int offset() default -1;

	/**
	 * Static length of this field within the header in bits. This parameter
	 * specifies in bits, the exact length of the annotated field within the
	 * current header. The value is constant. If length of the field is not
	 * constant but varies and can only be determined at runtime, then this
	 * parameter should not be used. Instead use a method and mark it with
	 * <code>@FieldRuntime(FieldFunction.LENGTH)</code> annotation.
	 * @return length of the field in bits
	 */
	int length() default -1;

	/**
	 * Name of the field. By default, the name of the field is determined
	 * implicitely by using the name of the method. This parameter allows the name
	 * of the field to be explicitely specified. The name of the field, must be
	 * unique within the same header and acts as a unique ID of the field.
	 * 
	 * @return name of the field
	 */
	String name() default EMPTY;

	/**
	 * Name of the field that will be displayed. The name is used by defaul if
	 * display parameter is not set. Display is only a text string that gets
	 * displayed as the name of the field. The actual content of this parameter
	 * have no baring on the name of the field.
	 * 
	 * @return display string to use as a display for field name
	 */
	String display() default EMPTY;

	/**
	 * A short name of the field to display. Nicname is similar to display
	 * parameter. It does not affect the name of the field and is only used for
	 * display purposes where appropriate.
	 * 
	 * @return short name of the filed
	 */
	String nicname() default EMPTY;

	/**
	 * A formatting string for the value of the field. Default is "%s".
	 * 
	 * @return field's formatting string
	 */
	String format() default DEFAULT_FORMAT;

	/**
	 * Units associated with the value of the field.
	 * 
	 * @return string with the name of the units
	 */
	String units() default EMPTY;

	/**
	 * A short description of the field's value.
	 * 
	 * @return a string with value description
	 */
	String description() default EMPTY;

	/**
	 * Sets the parent field's name and implicitely declares this field to be a
	 * subfield of the parent.
	 * 
	 * @return name of the parent field this sub field is appart of
	 */
	String parent() default EMPTY;

	/**
	 * A priority this field is assigned which is used in determining which field
	 * to include in output depending on what JFormat.Detail level the user has
	 * selected. Default is <code>Priority.MEDIUM</code>.
	 * 
	 * @return display priority of the field.
	 */
	Priority priority() default Priority.MEDIUM;

}
