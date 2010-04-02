/***************************************************************************
 * Copyright (C) 2007, Sly Technologies, Inc                               *
 * Distributed under the Lesser GNU Public License  (LGPL)                 *
 ***************************************************************************/

/*
 * Utility file that provides various conversion methods for chaging objects
 * back and forth between C and Java JNI.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/******
 ** Temporarily backed out of C++
 *
#include <cstdarg> // C++ declares varargs here
 ******/

#ifndef WIN32
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#endif /*WIN32*/

#include "util_debug.h"
#include "jnp.h"

/*
 * Some debug functionality
 */
const char *indent_template = "                            ";
char indent_buffer[1024 * 10] = {'\0'};
int indent = -1;
char indent_char = DEFAULT_INDENT_CHAR;
const char *last_method[100];
uint64_t debug_flags = 0L;

int debug_level = DEFAULT_LEVEL;

int  debug_get_level() {
	return debug_level;
}

void debug_set_level(int level) {
	debug_level = level;
}

char *to_buf() {
	if (indent >= 0) {
		sprintf(indent_buffer, "%s", last_method[0]);
	} else {
		indent_buffer[0] = '\0';
	}
	
	for (int i = 1; i <= indent; i++) {
		strcat(indent_buffer, ".");
		strcat(indent_buffer, last_method[i]);
	}

	return indent_buffer;
}

void debug_inc(const char *name) {
	if (indent < DEBUG_MAX_LEVEL) { // Safety check
		indent ++;
	} 
	
	last_method[indent] = name;
	
	to_buf();
}

void debug_dec() {
//	printf("debug_dec) - index=%d buf=%s\n", indent, indent_buffer);
	if (indent >= 0) { // Safety check
//		indent_buffer[--indent] = '\0';
//		sprintf(indent_buffer, "[%d]%s", --indent, last_method[indent]);
		indent --;

	} else {
//		indent_buffer[indent + 0] = '<'; // Indicates below min level
//		indent_buffer[indent + 1 ] = '\0';	
	}
	to_buf();
}

void debug_reset() {
	indent = 0;	
	indent_buffer[indent] = '\0';
	
}

char *debug_indent() {	
	if (indent  < 0) {
		return "";
	}
	
	return indent_buffer;
}

void debug_vmsg(const char *type, const char *fmt, va_list ap) {
	char buf[1024];
		
	vsprintf(buf, fmt, ap);
	printf("%s%s: "
			"%s"
			"\n",
			type, debug_indent(),
			buf);
	
	fflush(stdout);
}

void debug_msg(const char *type, const char *fmt, ...) {
	
	va_list ap;
	va_start(ap, fmt);

	debug_vmsg("", fmt, ap);

	va_end(ap);
}

void debug_trace(const char *fmt, ...) {
	if (debug_level < DEBUG_TRACE) {
		return;
	}
	
	va_list ap;
	va_start(ap, fmt);
	
	debug_vmsg("[TRACE]", fmt, ap);
	
	va_end(ap);
}

void debug_warn(const char *fmt, ...) {
	if (debug_level < DEBUG_WARN) {
		return;
	}
	
	va_list ap;
	va_start(ap, fmt);
	
	debug_vmsg("[WARN ]", fmt, ap);
	
	va_end(ap);
}

void debug_error(const char *fmt, ...) {
	if (debug_level < DEBUG_ERROR) {
		return;
	}
	
	va_list ap;
	va_start(ap, fmt);
	
	debug_vmsg("[ERROR]", fmt, ap);
	
	va_end(ap);
}

void debug_info(const char *fmt, ...) {
	if (debug_level < DEBUG_INFO) {
		return;
	}
	
	va_list ap;
	va_start(ap, fmt);
	
	debug_vmsg("[INFO]", fmt, ap);
	
	va_end(ap);
}


void debug_enter(const char *method) {
	debug_inc(method);
//	last_method[indent] = method;
	debug_trace("");
}

int debug_exit() {
	to_buf();
	
	debug_trace(jnp_perror());
	debug_dec();
	
	if (debug_flags & (1L << indent)) {
		debug_flags &= ~(1L << indent);
		return debug_exit();
	}
	
	return jnp_error();
}

int debug_exit_after() {

	debug_flags |= (1L << indent);
	
	return jnp_error();
}




/******
 ** Temporarily backed out of C++
 *


Debug Debug::global_logger("global", ERR);
Debug Debug::null_logger("global", NONE);

Debug::Debug(const char *name, Level defaultLevel) {
	reset();
	indentChar = DEFAULT_INDENT_CHAR;
	level = defaultLevel;
	Debug::parent = NULL;
	
	strcpy(Debug::name, name);
}


Debug::Debug(const char *name, Debug *parent) {
	reset();
	indentChar = DEFAULT_INDENT_CHAR;
	level = UNDEFINED;
	Debug::parent = parent;
	
	strcpy(Debug::name, name);
}


Debug::Debug(const char *name) {
	reset();
	indentChar = DEFAULT_INDENT_CHAR;
	level = ERR;
	Debug::parent = &global_logger;
	strcpy(Debug::name, name);
}

void Debug::inc() {
	
	if (parent != NULL) {
		parent->inc();
		return;
	}
	
	if (indentation < DEBUG_MAX_LEVEL) { // Safety check
		indentBuffer[indentation] = indentChar;
		indentBuffer[++indentation] = '\0';
	} else {
		indentBuffer[indentation - 1] = '>'; // Indicates too many levels
		indentBuffer[indentation - 0] = '\0';
	}
}

void Debug::dec() {
	
	if (parent != NULL) {
		parent->dec();
		return;
	}

	if (indentation > 0) { // Safety check
		indentBuffer[--indentation] = '\0';
	} else {
		indentBuffer[indentation + 0] = '<'; // Indicates below min level
		indentBuffer[indentation + 1 ] = '\0';
	}
}

void Debug::reset() {
	if (parent != NULL) {
		parent->reset();
		return;
	}

	indentation = 0;	
	indentBuffer[indentation] = '\0';
}

Debug::Level Debug::getLevel() {
	if (level == UNDEFINED && parent != NULL) {
		return parent->getLevel();
	} else {
		return level;
	}
}

void Debug::setLevel(Level newLevel) {
	level = newLevel;
}

char *Debug::indent() {
	return indentBuffer;
}

char *Debug::levelNames[] = {
		"TRACE",
		"INFO",
		"WARN",
		"ERROR"
};

char *Debug::getLevelName(Level level) {
	return levelNames[level];
}

void Debug::msg(Level type, char *msg, char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);

	vmsg(type, fmt, ap);

	va_end(ap);
}

void Debug::vmsg(Level type, char *msg, char *fmt, va_list ap) {
	char buf[1024];
		
	vsprintf(buf, fmt, ap);
	printf("[%-5s]%-20s%s: "
			"%s"
			"\n",
			getLevelName(type), msg, indent(),
			buf);
	
	fflush(stdout);
}

void Debug::trace(char *msg, char *fmt, ...) {
	if (getLevel() < TRACE) {
		return;
	}
	
	va_list ap;
	va_start(ap, fmt);
	
	vmsg(TRACE, fmt, ap);
	
	va_end(ap);	
}

void Debug::info(char *msg, char *fmt, ...) {
	if (getLevel() < INFO) {
		return;
	}
	
	va_list ap;
	va_start(ap, fmt);
	
	vmsg(INFO, fmt, ap);
	
	va_end(ap);	
}
void Debug::warn(char *msg, char *fmt, ...) {
	if (getLevel() < WARN) {
		return;
	}
	
	va_list ap;
	va_start(ap, fmt);
	
	vmsg(WARN, fmt, ap);
	
	va_end(ap);	
}
void Debug::error(char *msg, char *fmt, ...) {
	if (getLevel() < ERR) {
		return;
	}
	
	va_list ap;
	va_start(ap, fmt);
	
	vmsg(ERR, fmt, ap);
	
	va_end(ap);	
}

void Debug::enter(char *method) {
	inc();
	trace("enter", ">>> %s() >>>", method);
}

void Debug::exit(char *method) {
	trace("exit", "<<< %s() <<<", method);
	dec();
}


***********/
