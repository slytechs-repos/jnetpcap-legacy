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
package org.jnetpcap.packet.structure;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.List;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.annotate.FieldDefinitionException;
import org.jnetpcap.packet.annotate.FieldRuntime;
import org.jnetpcap.packet.annotate.FieldRuntime.FieldFunction;

/**
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public abstract class AnnotatedFieldMethod
    extends AnnotatedMethod {

	private static class BooleanFunction
	    extends AnnotatedFieldMethod {

		private boolean hasStaticValue = false;

		private boolean value;

		/**
		 * @param field
		 * @param function
		 * @param staticValue
		 */
		public BooleanFunction(AnnotatedField field, FieldFunction function) {
			super(field, function);

			setValue(true); // Static fields are always available
		}

		public BooleanFunction(Method method, FieldFunction function) {
			super(method, function);
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.packet.AnnotatedFieldMethod#booleanMethod(org.jnetpcap.packet.JHeader)
		 */
		@Override
		public boolean booleanMethod(JHeader header) {
			return execute(header);
		}

		public final void configFromField(AnnotatedField field) {

			switch (function) {
				case CHECK:
					break;

				default:
					throw new HeaderDefinitionError(
					    "Invalid FieldRuntime function type " + function.toString());

			}
			
			if (hasStaticValue == false && method == null) {
				throw new FieldDefinitionException(field, "Missing '"
				    + function.name().toLowerCase()
				    + "' property. [@FieldRuntime(FieldFunction." + function.name()
				    + ")]");
			}
		}

		public boolean execute(JHeader header) {
			if (hasStaticValue) {
				return this.value;
			}

			try {
				return (boolean) (Boolean) method.invoke(header);

			} catch (IllegalArgumentException e) {
				throw new IllegalStateException(e);
			} catch (IllegalAccessException e) {
				throw new IllegalStateException(e);
			} catch (InvocationTargetException e) {
				throw new AnnotatedMethodException(declaringClass, e);
			}
		}

		@SuppressWarnings("unused")
		private void setValue(boolean value) {
			hasStaticValue = true;
			this.value = value;
		}
	}

	private static class IntFunction
	    extends AnnotatedFieldMethod {

		private boolean hasStaticValue = false;

		private int value;

		public IntFunction(AnnotatedField field, FieldFunction function) {
			super(field, function);

			configFromField(field);

		}

		public IntFunction(AnnotatedField field, FieldFunction function,
		    int staticValue) {
			super(field, function);

			setValue(staticValue);
		}

		public IntFunction(Method method, FieldFunction function) {
			super(method, function);
		}

		public final void configFromField(AnnotatedField field) {

			switch (function) {
				case LENGTH:
					if (field.getLength() != -1) {
						setValue(field.getLength());
					}
					break;

				case OFFSET:
					if (field.getOffset() != -1) {
						setValue(field.getOffset());
					}
					break;

				case MASK:

					if (field.isSubField() == false) {
						setValue(0);
						break;
					}

					if (field.getLength() != -1 && field.getOffset() != -1) {
						/*
						 * Figure out the mask from offset and length
						 */
						final int length = field.getLength();
						final int offset = field.getOffset();
						int mask = 0;
						for (int i = offset; i < offset + length; i++) {
							mask |= (1 << i);
						}
						setValue(mask);
					}
					break;

				default:
					throw new HeaderDefinitionError(
					    "Invalid FieldRuntime function type " + function.toString());

			}

			if (hasStaticValue == false && method == null) {
				throw new FieldDefinitionException(field, "Missing '"
				    + function.name().toLowerCase() + "' property. [@Field("
				    + function.name().toLowerCase()
				    + "=<int>) or @FieldRuntime(FieldFunction." + function.name()
				    + ")]");
			}

		}

		public int execute(JHeader header) {
			if (hasStaticValue) {
				return this.value;
			}

			try {
				return (int) (Integer) method.invoke(header);

			} catch (IllegalArgumentException e) {
				throw new IllegalStateException(e);
			} catch (IllegalAccessException e) {
				throw new IllegalStateException(e);
			} catch (InvocationTargetException e) {
				throw new AnnotatedMethodException(declaringClass, e);
			}
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.packet.AnnotatedFieldMethod#intMethod(org.jnetpcap.packet.JHeader)
		 */
		@Override
		public int intMethod(JHeader header) {
			return execute(header);
		}

		private void setValue(int value) {
			hasStaticValue = true;
			this.value = value;
		}
	}

	private static class ObjectFunction
	    extends AnnotatedFieldMethod {

		public ObjectFunction(AnnotatedField field, FieldFunction fuction) {
			super(field, fuction, field.getMethod());

		}

		public ObjectFunction(Method method, FieldFunction function) {
			super(method, function);
		}

		public final void configFromField(AnnotatedField field) {

			switch (function) {
				case VALUE:
					if (method == null) {
						throw new HeaderDefinitionError(field.getDeclaringClass(),
						    "no method set for field value getter [" + field.getName()
						        + "]");
					}
					break;

				default:
					throw new HeaderDefinitionError(field.getDeclaringClass(),
					    "Invalid FieldRuntime function type " + function.toString());

			}

			if (method == null) {
				throw new FieldDefinitionException(field, "Missing field accessor '"
				    + function.name().toLowerCase()
				    + "' property. [@FieldRuntime(FieldFunction." + function.name()
				    + ")]");
			}
		}

		public Object execute(JHeader header) {

			try {
				return method.invoke(header);

			} catch (IllegalArgumentException e) {
				throw new IllegalStateException(e);
			} catch (IllegalAccessException e) {
				throw new IllegalStateException(e);
			} catch (InvocationTargetException e) {
				throw new AnnotatedMethodException(declaringClass, e);
			}
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.packet.AnnotatedFieldMethod#objectMethod(org.jnetpcap.packet.JHeader)
		 */
		@Override
		public Object objectMethod(JHeader header) {
			return execute(header);
		}
	}

	private static class StringFunction
	    extends AnnotatedFieldMethod {

		private boolean hasStaticValue = false;

		private String value;

		/**
		 * @param field
		 * @param function
		 */
		public StringFunction(AnnotatedField field, FieldFunction function) {
			super(field, function);

			configFromField(field);
		}

		public StringFunction(Method method, FieldFunction function) {
			super(method, function);
		}

		public final void configFromField(AnnotatedField field) {

			switch (function) {
				case UNITS:
					if (field.getUnits().length() != 0) {
						setValue(field.getUnits());
					} else if (method == null) {
						setValue(null);
					}
					break;
				case DISPLAY:
					if (field.getDisplay().length() != 0) {
						setValue(field.getDisplay());
					} else if (method == null) {
						setValue(null);
					}
					break;

				case DESCRIPTION:
					if (field.getDescription().length() != 0) {
						setValue(field.getDescription());
					} else if (method == null) {
						setValue(null);
					}
					break;

				default:
					throw new HeaderDefinitionError(
					    "Invalid FieldRuntime function type " + function.toString());

			}
			
			if (hasStaticValue == false && method == null) {
				throw new FieldDefinitionException(field, "Missing '"
				    + function.name().toLowerCase()
				    + "' property. [@Field("
				    + function.name().toLowerCase()
				    + "=<string>) or @FieldRuntime(FieldFunction." + function.name()
				    + ")]");
			}
		}

		public String execute(JHeader header) {
			if (hasStaticValue) {
				return this.value;
			}

			try {
				return (String) method.invoke(header);

			} catch (IllegalArgumentException e) {
				throw new IllegalStateException(e);
			} catch (IllegalAccessException e) {
				throw new IllegalStateException(e);
			} catch (InvocationTargetException e) {
				throw new AnnotatedMethodException(declaringClass, e);
			}
		}

		private void setValue(String value) {
			hasStaticValue = true;
			this.value = value;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.packet.AnnotatedFieldMethod#StringMethod(org.jnetpcap.packet.JHeader)
		 */
		@Override
		public String stringMethod(JHeader header) {
			return execute(header);
		}
	}

	/**
	 * @param runtime
	 */
	public static void checkAnnotation(Method method, List<AnnotatedField> fields) {

		FieldRuntime runtime = method.getAnnotation(FieldRuntime.class);

		if (runtime.field().length() != 0) {

			boolean found = false;
			final String name = runtime.field();
			for (AnnotatedField f : fields) {
				if (f.getName().equals(name)) {
					found = true;
					break;
				}
			}

			if (!found) {
				throw new HeaderDefinitionError("field name defined in annotation ");
			}

		}
	}

	/**
	 * @param method
	 */
	private static void checkBooleanSignature(Method method) {
		final Class<?> declaringClass = method.getDeclaringClass();

		/*
		 * Now make sure it has the right signature of: <code>String name()</code.
		 */
		final Class<?>[] sig = method.getParameterTypes();
		if (sig.length != 0 || method.getReturnType() != boolean.class) {
			throw new AnnotatedMethodException(declaringClass,
			    "Invalid signature for " + method.getName() + "()");
		}

		if ((method.getModifiers() & Modifier.STATIC) != 0) {
			throw new AnnotatedMethodException(declaringClass, method.getName()
			    + "()" + " can not be declared static");
		}
	}

	/**
	 * @param method
	 */
	private static void checkIntSignature(Method method) {
		final Class<?> declaringClass = method.getDeclaringClass();

		/*
		 * Now make sure it has the right signature of: <code>String name()</code.
		 */
		final Class<?>[] sig = method.getParameterTypes();
		if (sig.length != 0 || method.getReturnType() != int.class) {
			throw new AnnotatedMethodException(declaringClass,
			    "Invalid signature for " + method.getName() + "()");
		}

		if ((method.getModifiers() & Modifier.STATIC) != 0) {
			throw new AnnotatedMethodException(declaringClass, method.getName()
			    + "()" + " can not be declared static");
		}
	}

	/**
	 * @param method
	 */
	private static void checkObjectSignature(Method method) {
		final Class<?> declaringClass = method.getDeclaringClass();

		/*
		 * Now make sure it has the right signature of: <code>anythign name()</code.
		 */
		final Class<?>[] sig = method.getParameterTypes();
		if (sig.length != 0) {
			throw new AnnotatedMethodException(declaringClass,
			    "Invalid signature for " + method.getName() + "()");
		}

		if ((method.getModifiers() & Modifier.STATIC) != 0) {
			throw new AnnotatedMethodException(declaringClass, method.getName()
			    + "()" + " can not be declared static");
		}
	}

	/**
	 * @param method
	 */
	private static void checkStringSignature(Method method) {
		final Class<?> declaringClass = method.getDeclaringClass();

		/*
		 * Now make sure it has the right signature of: <code>String name()</code.
		 */
		final Class<?>[] sig = method.getParameterTypes();
		if (sig.length != 0 || method.getReturnType() != String.class) {
			throw new AnnotatedMethodException(declaringClass,
			    "Invalid signature for " + method.getName() + "()");
		}

		if ((method.getModifiers() & Modifier.STATIC) != 0) {
			throw new AnnotatedMethodException(declaringClass, method.getName()
			    + "()" + " can not be declared static");
		}
	}

	public static AnnotatedFieldMethod generateFunction(
	    FieldFunction function,
	    AnnotatedField field) {

		switch (function) {
			case LENGTH:
			case OFFSET:
				return new IntFunction(field, function);

			case MASK:
				if (field.isSubField()) {
					/**
					 * Expect length and offset to be set in field
					 */
					return new IntFunction(field, function);
				} else {
					/*
					 * A function that always returns a 0
					 */
					return new IntFunction(field, function, 0);
				}

			case VALUE:
				return new ObjectFunction(field, function);

			case CHECK:
				return new BooleanFunction(field, function);

			case UNITS:
			case DISPLAY:
			case DESCRIPTION:
				return new StringFunction(field, function);

			default:
				throw new HeaderDefinitionError(
				    "Unsupported FieldRuntime function type " + function.toString());
		}

	}

	private static String guessFieldName(String name) {
		if (name.endsWith("Description")) {
			return name.replace("Description", "");
		} else if (name.endsWith("Offset")) {
			return name.replace("Offset", "");
		} else if (name.endsWith("Length")) {
			return name.replace("Length", "");
		} else if (name.endsWith("Mask")) {
			return name.replace("Mask", "");
		} else if (name.endsWith("Value")) {
			return name.replace("Value", "");
		} else if (name.startsWith("has")) {
			String cap = name.replace("has", "");
			char u = cap.charAt(0);
			char l = Character.toLowerCase(u);
			return cap.replace(u, l);
		} else {
			return name;
		}
	}

	/**
	 * @param method
	 * @return
	 */
	public static AnnotatedFieldMethod inspectMethod(Method method) {

		FieldRuntime runtime = method.getAnnotation(FieldRuntime.class);

		FieldFunction function = runtime.value();
		switch (function) {
			case LENGTH:
			case MASK:
			case OFFSET:
				checkIntSignature(method);
				return new IntFunction(method, function);

			case VALUE:
				checkObjectSignature(method);

				return new ObjectFunction(method, function);

			case CHECK:
				checkBooleanSignature(method);
				return new BooleanFunction(method, function);

			case DESCRIPTION:
				checkStringSignature(method);
				return new StringFunction(method, function);

			default:
				throw new HeaderDefinitionError(
				    "Unsupported FieldRuntime function type " + function.toString());
		}
	}

	protected final String field;

	protected final FieldFunction function;

	public AnnotatedFieldMethod(AnnotatedField field, FieldFunction function) {
		super();
		this.function = function;

		this.field = field.getName();
	}

	public AnnotatedFieldMethod(AnnotatedField field, FieldFunction function,
	    Method method) {
		super(method);
		this.function = function;

		this.field = field.getName();
	}

	/**
	 * @param method
	 */
	public AnnotatedFieldMethod(Method method, FieldFunction function) {
		super(method);
		this.function = function;

		FieldRuntime runtime = method.getAnnotation(FieldRuntime.class);
		if (runtime == null) {
			throw new HeaderDefinitionError(method.getDeclaringClass(),
			    "unable get field's annotated runtime");
		}

		if (runtime.field().length() != 0) {
			this.field = runtime.field();
		} else {
			this.field = guessFieldName(method.getName());
		}
	}

	public boolean booleanMethod(JHeader header) {
		throw new UnsupportedOperationException(
		    "this return type is invalid for this function type");
	}

	public abstract void configFromField(AnnotatedField field);

	public String getFieldName() {
		return field;
	}

	public final FieldFunction getFunction() {
		return this.function;
	}

	public int intMethod(JHeader header) {
		throw new UnsupportedOperationException(
		    "this return type is invalid for this function type");
	}

	public Object objectMethod(JHeader header) {
		throw new UnsupportedOperationException(
		    "this return type is invalid for this function type");
	}

	public String stringMethod(JHeader header) {
		throw new UnsupportedOperationException(
		    "this return type is invalid for this function type");
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jnetpcap.packet.AnnotatedMethod#validateSignature(java.lang.reflect.Method)
	 */
	@Override
	protected void validateSignature(Method method) {
	}

}
