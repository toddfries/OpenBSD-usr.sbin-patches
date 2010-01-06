/* A Bison parser, made by GNU Bison 2.3.  */

/* Skeleton interface for Bison's Yacc-like parsers in C

   Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002, 2003, 2004, 2005, 2006
   Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02110-1301, USA.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     SPACE = 258,
     LETTER = 259,
     NEWLINE = 260,
     COMMENT = 261,
     COLON = 262,
     ANY = 263,
     ZONESTR = 264,
     STRING = 265,
     VAR_SERVER = 266,
     VAR_NAME = 267,
     VAR_IP_ADDRESS = 268,
     VAR_DEBUG_MODE = 269,
     VAR_IP4_ONLY = 270,
     VAR_IP6_ONLY = 271,
     VAR_DATABASE = 272,
     VAR_IDENTITY = 273,
     VAR_LOGFILE = 274,
     VAR_SERVER_COUNT = 275,
     VAR_TCP_COUNT = 276,
     VAR_PIDFILE = 277,
     VAR_PORT = 278,
     VAR_STATISTICS = 279,
     VAR_CHROOT = 280,
     VAR_USERNAME = 281,
     VAR_ZONESDIR = 282,
     VAR_XFRDFILE = 283,
     VAR_DIFFFILE = 284,
     VAR_XFRD_RELOAD_TIMEOUT = 285,
     VAR_TCP_QUERY_COUNT = 286,
     VAR_TCP_TIMEOUT = 287,
     VAR_IPV4_EDNS_SIZE = 288,
     VAR_IPV6_EDNS_SIZE = 289,
     VAR_ZONEFILE = 290,
     VAR_ZONE = 291,
     VAR_ALLOW_NOTIFY = 292,
     VAR_REQUEST_XFR = 293,
     VAR_NOTIFY = 294,
     VAR_PROVIDE_XFR = 295,
     VAR_NOTIFY_RETRY = 296,
     VAR_OUTGOING_INTERFACE = 297,
     VAR_ALLOW_AXFR_FALLBACK = 298,
     VAR_KEY = 299,
     VAR_ALGORITHM = 300,
     VAR_SECRET = 301,
     VAR_AXFR = 302,
     VAR_UDP = 303,
     VAR_VERBOSITY = 304,
     VAR_HIDE_VERSION = 305
   };
#endif
/* Tokens.  */
#define SPACE 258
#define LETTER 259
#define NEWLINE 260
#define COMMENT 261
#define COLON 262
#define ANY 263
#define ZONESTR 264
#define STRING 265
#define VAR_SERVER 266
#define VAR_NAME 267
#define VAR_IP_ADDRESS 268
#define VAR_DEBUG_MODE 269
#define VAR_IP4_ONLY 270
#define VAR_IP6_ONLY 271
#define VAR_DATABASE 272
#define VAR_IDENTITY 273
#define VAR_LOGFILE 274
#define VAR_SERVER_COUNT 275
#define VAR_TCP_COUNT 276
#define VAR_PIDFILE 277
#define VAR_PORT 278
#define VAR_STATISTICS 279
#define VAR_CHROOT 280
#define VAR_USERNAME 281
#define VAR_ZONESDIR 282
#define VAR_XFRDFILE 283
#define VAR_DIFFFILE 284
#define VAR_XFRD_RELOAD_TIMEOUT 285
#define VAR_TCP_QUERY_COUNT 286
#define VAR_TCP_TIMEOUT 287
#define VAR_IPV4_EDNS_SIZE 288
#define VAR_IPV6_EDNS_SIZE 289
#define VAR_ZONEFILE 290
#define VAR_ZONE 291
#define VAR_ALLOW_NOTIFY 292
#define VAR_REQUEST_XFR 293
#define VAR_NOTIFY 294
#define VAR_PROVIDE_XFR 295
#define VAR_NOTIFY_RETRY 296
#define VAR_OUTGOING_INTERFACE 297
#define VAR_ALLOW_AXFR_FALLBACK 298
#define VAR_KEY 299
#define VAR_ALGORITHM 300
#define VAR_SECRET 301
#define VAR_AXFR 302
#define VAR_UDP 303
#define VAR_VERBOSITY 304
#define VAR_HIDE_VERSION 305




#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
#line 39 "configparser.y"
{
	char*	str;
}
/* Line 1489 of yacc.c.  */
#line 153 "configparser.h"
	YYSTYPE;
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif

extern YYSTYPE yylval;

