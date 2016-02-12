/* All the functions in this file runs with aLua stack, and can
 * return with a longjmp. All of these function must be launched
 * in an environment able to catch a longjmp, otherwise a
 * critical error can be raised.
 */
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

#include <common/time.h>

/* Contains the class reference of the concat object. */
static int class_concat_ref;

/* Return an object of the expected type, or throws an error. */
void *hlua_checkudata(lua_State *L, int ud, int class_ref)
{
	void *p;
	int ret;

	/* Check if the stack entry is an array. */
	if (!lua_istable(L, ud))
		luaL_argerror(L, ud, NULL);

	/* pop the metatable of the referencecd object. */
	if (!lua_getmetatable(L, ud))
		luaL_argerror(L, ud, NULL);

	/* pop the expected metatable. */
	lua_rawgeti(L, LUA_REGISTRYINDEX, class_ref);

	/* Check if the metadata have the expected type. */
	ret = lua_rawequal(L, -1, -2);
	lua_pop(L, 2);
	if (!ret)
		luaL_argerror(L, ud, NULL);

	/* Push on the stack at the entry [0] of the table. */
	lua_rawgeti(L, ud, 0);

	/* Check if this entry is userdata. */
	p = lua_touserdata(L, -1);
	if (!p)
		luaL_argerror(L, ud, NULL);

	/* Remove the entry returned by lua_rawgeti(). */
	lua_pop(L, 1);

	/* Return the associated struct. */
	return p;
}

/* This function return the current date at epoch format in milliseconds. */
int hlua_now(lua_State *L)
{
	lua_newtable(L);
	lua_pushstring(L, "sec");
	lua_pushinteger(L, now.tv_sec);
	lua_rawset(L, -3);
	lua_pushstring(L, "usec");
	lua_pushinteger(L, now.tv_usec);
	lua_rawset(L, -3);
	return 1;
}

/* This functions expects a Lua string as HTTP date, parse it and
 * returns an integer containing the epoch format of the date, or
 * nil if the parsing fails.
 */
static int hlua_parse_date(lua_State *L, int (*fcn)(const char *, int, struct tm*))
{
	const char *str;
	size_t len;
	struct tm tm;
	time_t time;

	str = luaL_checklstring(L, 1, &len);

	if (!fcn(str, len, &tm)) {
		lua_pushnil(L);
		return 1;
	}

	/* This function considers the content of the broken-down time
	 * is exprimed in the UTC timezone. timegm don't care about
	 * the gnu variable tm_gmtoff. If gmtoff is set, or if you know
	 * the timezone from the broken-down time, it must be fixed
	 * after the conversion.
	 */
	time = timegm(&tm);
	if (time == -1) {
		lua_pushnil(L);
		return 1;
	}

	lua_pushinteger(L, (int)time);
	return 1;
}
static int hlua_http_date(lua_State *L)
{
	return hlua_parse_date(L, parse_http_date);
}
static int hlua_imf_date(lua_State *L)
{
	return hlua_parse_date(L, parse_imf_date);
}
static int hlua_rfc850_date(lua_State *L)
{
	return hlua_parse_date(L, parse_rfc850_date);
}
static int hlua_asctime_date(lua_State *L)
{
	return hlua_parse_date(L, parse_asctime_date);
}

static void hlua_array_add_fcn(lua_State *L, const char *name,
                               int (*function)(lua_State *L))
{
	lua_pushstring(L, name);
	lua_pushcclosure(L, function, 0);
	lua_rawset(L, -3);
}

static luaL_Buffer *hlua_check_concat(lua_State *L, int ud)
{
	return (luaL_Buffer *)(hlua_checkudata(L, ud, class_concat_ref));
}

static int hlua_concat_add(lua_State *L)
{
	luaL_Buffer *b;
	const char *str;
	size_t l;

	/* First arg must be a concat object. */
	b = hlua_check_concat(L, 1);

	/* Second arg must be a string. */
	str = luaL_checklstring(L, 2, &l);

	luaL_addlstring(b, str, l);
	return 0;
}

static int hlua_concat_dump(lua_State *L)
{
	luaL_Buffer *b;

	/* First arg must be a concat object. */
	b = hlua_check_concat(L, 1);

	/* Push the soncatenated strng in the stack. */
	luaL_pushresult(b);
	return 1;
}

int hlua_concat_new(lua_State *L)
{
	luaL_Buffer *b;

	lua_newtable(L);
	b = lua_newuserdata(L, sizeof(luaL_Buffer));
	lua_rawseti(L, -2, 0);

	lua_rawgeti(L, LUA_REGISTRYINDEX, class_concat_ref);
	lua_setmetatable(L, -2);

	luaL_buffinit(L, b);
	return 1;
}

static int concat_tostring(lua_State *L)
{
	const void *ptr = lua_topointer(L, 1);
	lua_pushfstring(L, "Concat object: %p", ptr);
	return 1;
}

static int hlua_concat_init(lua_State *L)
{
	/* Creates the buffered concat object. */
	lua_newtable(L);

	lua_pushstring(L, "__tostring");
	lua_pushcclosure(L, concat_tostring, 0);
	lua_settable(L, -3);

	lua_pushstring(L, "__index"); /* Creates the index entry. */
	lua_newtable(L); /* The "__index" content. */

	lua_pushstring(L, "add");
	lua_pushcclosure(L, hlua_concat_add, 0);
	lua_settable(L, -3);

	lua_pushstring(L, "dump");
	lua_pushcclosure(L, hlua_concat_dump, 0);
	lua_settable(L, -3);

	lua_settable(L, -3); /* Sets the __index entry. */
	class_concat_ref = luaL_ref(L, LUA_REGISTRYINDEX);

	return 1;
}

int hlua_fcn_reg_core_fcn(lua_State *L)
{
	if (!hlua_concat_init(L))
		return 0;

	hlua_array_add_fcn(L, "now", hlua_now);
	hlua_array_add_fcn(L, "http_date", hlua_http_date);
	hlua_array_add_fcn(L, "imf_date", hlua_imf_date);
	hlua_array_add_fcn(L, "rfc850_date", hlua_rfc850_date);
	hlua_array_add_fcn(L, "asctime_date", hlua_asctime_date);
	hlua_array_add_fcn(L, "concat", hlua_concat_new);
	return 5;
}
