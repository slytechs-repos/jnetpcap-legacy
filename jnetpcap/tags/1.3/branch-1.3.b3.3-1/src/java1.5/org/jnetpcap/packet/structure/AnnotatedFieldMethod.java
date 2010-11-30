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
import org.jnetpcap.packet.annotate.Dynamic;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.FieldDefinitionException;

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
		public BooleanFunction(AnnotatedField field, Field.Property function) {
			super(field, function);

			setValue(true); // Static fields are always available
		}

		public BooleanFunction(Method method, Field.Property function) {
			super(method, function);
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.packet.AnnotatedFieldMethod#booleanMethod(org.jnetpcap.packet.JHeader)
		 */
		@Override
		public boolean booleanMethod(JHeader header, String name) {
			return execute(header, name);
		}

		public final void configFromField(AnnotatedField field) {

			switch (function) {
				case CHECK:
					break;

				default:
					throw new HeaderDefinitionError("Invalid Dynamic function type "
					    + function.toString());

			}

			if (hasStaticValue == false && method == null) {
				throw new FieldDefinitionException(field, "Missing '"
				    + function.name().toLowerCase() + "' property. [@Dynamic(Property."
				    + function.name() + ")]");
			}
		}

		public boolean execute(JHeader header, String name) {
			if (hasStaticValue) {
				return this.value;
			}

			try {
				if (isMapped) {
					return (boolean) (Boolean) method.invoke(header, name);
				} else {
					return (boolean) (Boolean) method.invoke(header);
				}

			} catch (IllegalArgumentException e) {
				throw new IllegalStateException(e);
			} catch (IllegalAccessException e) {
				throw new IllegalStateException(e);
			} catch (InvocationTargetException e) {
				throw new AnnotatedMethodException(declaringClass, e);
			}
		}

		private void setValue(boolean value) {
			hasStaticValue = true;
			this.value = value;
		}
	}

	private static class IntFunction
	    extends AnnotatedFieldMethod {

		private boolean hasStaticValue = false;

		private int value;

		public IntFunction(AnnotatedField field, Field.Property function) {
			super(field, function);

			configFromField(field);

		}

		public IntFunction(AnnotatedField field, Field.Property function,
		    int staticValue) {
			super(field, function);

			setValue(staticValue);
		}

		public IntFunction(Method method, Field.Property function) {
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

				default:
					throw new HeaderDefinitionError("Invalid Dynamic function type "
					    + function.toString());

			}

			if (hasStaticValue == false && method == null) {
				throw new FieldDefinitionException(field, "Missing '"
				    + function.name().toLowerCase() + "' property. [@Field("
				    + function.name().toLowerCase() + "=<int>) or @Dynamic(Property."
				    + function.name() + ")]");
			}

		}

		public int execute(JHeader header, String name) {
			if (hasStaticValue) {
				return this.value;
			}

			try {
				if (isMapped) {
					return (int) (Integer) method.invoke(header, name);
				} else {
					return (int) (Integer) method.invoke(header);
				}

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
		public int intMethod(JHeader header, String name) {
			return execute(header, name);
		}

		private void setValue(int value) {
			hasStaticValue = true;
			this.value = value;
		}
	}

	private static class LongFunction
	    extends AnnotatedFieldMethod {

		private boolean hasStaticValue = false;

		private long value;

		public LongFunction(AnnotatedField field, Field.Property function) {
			super(field, function);

			configFromField(field);

		}

		public LongFunction(AnnotatedField field, Field.Property function,
		    long staticValue) {
			super(field, function);

			setValue(staticValue);
		}

		public LongFunction(Method method, Field.Property function) {
			super(method, function);
		}

		public final void configFromField(AnnotatedField field) {

			switch (function) {

				case MASK:

					setValue(field.getMask());
					break;

				default:
					throw new HeaderDefinitionError("Invalid Dynamic function type "
					    + function.toString());

			}

			if (hasStaticValue == false && method == null) {
				throw new FieldDefinitionException(field, "Missing '"
				    + function.name().toLowerCase() + "' property. [@Field("
				    + function.name().toLowerCase() + "=<int>) or @Dynamic(Property."
				    + function.name() + ")]");
			}

		}

		public long execute(JHeader header, String name) {
			if (hasStaticValue) {
				return this.value;
			}

			try {
				if (isMapped) {
					return (long) (Long) method.invoke(header, name);
				} else {
					return (long) (Long) method.invoke(header);
				}

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
		 * @see org.jnetpcap.packet.AnnotatedFieldMethod#longMethod(org.jnetpcap.packet.JHeader)
		 */
		@Override
		public long longMethod(JHeader header, String name) {
			return execute(header, name);
		}

		private void setValue(long mask) {
			hasStaticValue = true;
			this.value = mask;
		}
	}

	private static class ObjectFunction
	    extends AnnotatedFieldMethod {

		public ObjectFunction(AnnotatedField field, Field.Property fuction) {
			super(field, fuction, field.getMethod());

		}

		public ObjectFunction(Method method, Field.Property function) {
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
					    "Invalid Dynamic function type " + function.toString());

			}

			if (method == null) {
				throw new FieldDefinitionException(field, "Missing field accessor '"
				    + function.name().toLowerCase() + "' property. [@Dynamic(Property."
				    + function.name() + ")]");
			}
		}

		public Object execute(JHeader header, String name) {

			try {
				if (isMapped) {
					return method.invoke(header, name);
				} else {
					return method.invoke(header);
				}

			} catch (IllegalArgumentException e) {
				throw new IllegalStateException(e);
			} catch (IllegalAccessException e) {
				throw new IllegalStateException(e);
			} catch (InvocationTargetException e) {
				throw new AnnotatedMethodException(declaringClass, e.getMessage(), e);
			}
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.jnetpcap.packet.AnnotatedFieldMethod#objectMethod(org.jnetpcap.packet.JHeader)
		 */
		@Override
		public Object objectMethod(JHeader header, String name) {
			return execute(header, name);
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
		public StringFunction(AnnotatedField field, Field.Property function) {
			super(field, function);

			configFromField(field);
		}

		public StringFunction(Method method, Field.Property function) {
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
					throw new HeaderDefinitionError("Invalid Dynamic function type "
					    + function.toString());

			}

			if (hasStaticValue == false && method == null) {
				throw new FieldDefinitionException(field, "Missing '"
				    + function.name().toLowerCase() + "' property. [@Field("
				    + function.name().toLowerCase()
				    + "=<string>) or @Dynamic(Property." + function.name() + ")]");
			}
		}

		public String execute(JHeader header, String name) {
			if (hasStaticValue) {
				return this.value;
			}

			try {
				if (isMapped) {
					return (String) method.invoke(header, name);
				} else {
					return (String) method.invoke(header);
				}

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
		public String stringMethod(JHeader header, String name) {
			return execute(header, name);
		}
	}

	/**
	 * @param runtime
	 */
	public static void checkAnnotation(Method method, List<AnnotatedField> fields) {

		Dynamic runtime = method.getAnnotation(Dynamic.class);

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

	private static void checkSignature(Method method, Class<?> c) {
		final Class<?> declaringClass = method.getDeclaringClass();

		/*
		 * Now make sure it has the right signature of: <code>String name()</code.
		 */
		final Class<?>[] sig = method.getParameterTypes();
		if ((sig.length == 1 && sig[0] != String.class) || sig.length > 1
		    || method.getReturnType() != c) {
			throw new AnnotatedMethodException(declaringClass,
			    "Invalid signature for " + method.getName() + "()");
		}

		if ((method.getModifiers() & Modifier.STATIC) != 0) {
			throw new AnnotatedMethodException(declaringClass, method.getName()
			    + "()" + " can not be declared static");
		}
	}

	public static AnnotatedFieldMethod generateFunction(
	    Field.Property function,
	    AnnotatedField field) {

		switch (function) {
			case LENGTH:
			case OFFSET:
				return new IntFunction(field, function);

			case MASK:
				return new LongFunction(field, function);

			case VALUE:
				return new ObjectFunction(field, function);

			case CHECK:
				return new BooleanFunction(field, function);

			case UNITS:
			case DISPLAY:
			case DESCRIPTION:
				return new StringFunction(field, function);

			default:
				throw new HeaderDefinitionError("Unsupported Dynamic function type "
				    + function.toString());
		}

	}

	private static String guessFieldName(String name) {
		if (name.startsWith("has")) {
			String cap = name.replace("has", "");
			char u = cap.charAt(0);
			char l = Character.toLowerCase(u);
			return cap.replace(u, l);
		} else if (name.endsWith("Description")) {
			return name.replace("Description", "");
		} else if (name.endsWith("Offset")) {
			return name.replace("Offset", "");
		} else if (name.endsWith("Length")) {
			return name.replace("Length", "");
		} else if (name.endsWith("Mask")) {
			return name.replace("Mask", "");
		} else if (name.endsWith("Value")) {
			return name.replace("Value", "");
		} else if (name.endsWith("Display")) {
			return name.replace("Display", "");
		} else if (name.endsWith("Units")) {
			return name.replace("Units", "");
		} else if (name.endsWith("Format")) {
			return name.replace("Format", "");
		} else {
			return name;
		}
	}

	/**
	 * @param method
	 * @return
	 */
	public static AnnotatedFieldMethod inspectMethod(Method method) {

		Dynamic runtime = method.getAnnotation(Dynamic.class);

		Field.Property function = runtime.value();
		switch (function) {
			case LENGTH:
			case OFFSET:
				checkSignature(method, int.class);
				return new IntFunction(method, function);

			case MASK:
				checkSignature(method, long.class);
				return new LongFunction(method, function);

			case VALUE:
				checkSignature(method, Object.class);

				return new ObjectFunction(method, function);

			case CHECK:
				checkSignature(method, boolean.class);
				return new BooleanFunction(method, function);

			case DISPLAY:
			case DESCRIPTION:
				checkSignature(method, String.class);
				return new StringFunction(method, function);

			default:
				throw new HeaderDefinitionError("Unsupported Dynamic function type "
				    + function.toString());
		}
	}

	protected final String field;

	protected final Field.Property function;

	public AnnotatedFieldMethod(AnnotatedField field, Field.Property function) {
		super();
		this.function = function;

		this.field = field.getName();
	}

	public AnnotatedFieldMethod(AnnotatedField field, Field.Property function,
	    Method method) {
		super(method);
		this.function = function;

		this.field = field.getName();
	}

	/**
	 * @param method
	 */
	public AnnotatedFieldMethod(Method method, Field.Property function) {
		super(method);
		this.function = function;

		Dynamic runtime = method.getAnnotation(Dynamic.class);
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

	public boolean booleanMethod(JHeader header, String name) {
		throw new UnsupportedOperationException(
		    "this return type is invalid for this function type");
	}

	public abstract void configFromField(AnnotatedField field);

	public String getFieldName() {
		return field;
	}

	public final Field.Property getFunction() {
		return this.function;
	}

	public int intMethod(JHeader header, String name) {
		throw new UnsupportedOperationException(
		    "this return type is invalid for this function type");
	}

	public Object objectMethod(JHeader header, String name) {
		throw new UnsupportedOperationException(
		    "this return type is invalid for this function type");
	}

	public String stringMethod(JHeader header, String name) {
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

	/**
	 * @param header
	 * @return
	 */
	public long longMethod(JHeader header, String name) {
		throw new UnsupportedOperationException(
		    "this return type is invalid for this function type");
	}

}
