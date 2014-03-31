/***************************************************************************
 *
 * Copyright (c) 2000-2014 BalaBit IT Ltd, Budapest, Hungary
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation.
 *
 * Note that this permission is granted for only version 2 of the GPL.
 *
 * As an additional exemption you are allowed to compile & link against the
 * OpenSSL libraries as published by the OpenSSL project. See the file
 * COPYING for details.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Author  : Bazsi
 * Auditor :
 * Last audited version:
 * Notes:
 *
 ***************************************************************************/

#include <zorp/pystruct.h>

/* a generic wrapper for ZPolicyDict */
struct _ZPolicyStruct
{
  PyObject_HEAD
  ZPolicyDict *dict;
  ZPolicyStructFormatFunc format_func;
  gboolean is_config;
};

extern PyTypeObject z_policy_struct_types[Z_PST_MAX];
static void z_policy_struct_free(ZPolicyObj *s);

void
z_policy_struct_set_is_config(ZPolicyObj *s, gboolean is_config)
{
  ZPolicyStruct *self = (ZPolicyStruct *) s;

  self->is_config = is_config;
}

gboolean
z_policy_struct_check(ZPolicyObj *s, gint type)
{
  if (type)
    return s->ob_type == &z_policy_struct_types[type];
  return (void *) s->ob_type->tp_dealloc == (void *) z_policy_struct_free;
}

ZPolicyDict *
z_policy_struct_release_dict(ZPolicyObj *s)
{
  ZPolicyStruct *self = (ZPolicyStruct *) s;
  ZPolicyDict *dict;

  g_assert(z_policy_struct_check(s, 0));

  dict = self->dict;
  z_policy_dict_unwrap(dict, s);
  self->dict = NULL;

  return dict;
}

ZPolicyDict *
z_policy_struct_get_dict(ZPolicyObj *s)
{
  ZPolicyStruct *self = (ZPolicyStruct *) s;

  g_assert(z_policy_struct_check(s, 0));
  return self->dict;
}

void
z_policy_struct_set_format(ZPolicyObj *s, ZPolicyStructFormatFunc format)
{
  ZPolicyStruct *self = (ZPolicyStruct *) s;

  z_policy_struct_check(s, Z_PST_NONE);
  self->format_func = format;
}

static PyObject *
z_policy_struct_str(ZPolicyObj *s)
{
  ZPolicyStruct *self = (ZPolicyStruct *) s;

  if (self->format_func)
    {
      return self->format_func(s);
    }
  else
    {
      gchar buf[128];

      g_snprintf(buf, sizeof(buf), "ZPolicyStruct object type %s", self->ob_type->tp_name);
      return PyString_FromString(buf);
    }
}

static ZPolicyObj *
z_policy_struct_getattr(ZPolicyObj *s, gchar *name)
{
  ZPolicyStruct *self = (ZPolicyStruct *) s;
  ZPolicyObj *res;

  if (strcmp(name, "__dict__") == 0)
    {
      return z_policy_dict_get_dict(self->dict);
    }
  else
    {
      res = z_policy_dict_get_value(self->dict, self->is_config, name);
      if (!res)
        z_policy_raise_exception_obj(PyExc_AttributeError, "No such attribute");
    }
  return res;
}

static gint
z_policy_struct_setattr(ZPolicyObj *s, gchar *name, ZPolicyObj *new_value)
{
  ZPolicyStruct *self = (ZPolicyStruct *) s;
  gint res;

  res = z_policy_dict_set_value(self->dict, self->is_config, name, new_value);
  if (res < 0 && !PyErr_Occurred())
    {
       z_policy_raise_exception_obj(PyExc_AttributeError, "Error writing attribute");
       res = -1;
    }
  else if (res > 0)
    {
      /* not found in dict, create a new entry */
      z_policy_dict_register(self->dict, Z_VT_OBJECT, name,
                             Z_VF_RW | Z_VF_CFG_RW | Z_VF_LITERAL | Z_VF_CONSUME,
                             new_value);
      z_policy_var_ref(new_value);
      res = 0;
    }

  return res;
}

ZPolicyObj *
z_policy_struct_new(ZPolicyDict *dict, gint type)
{
  ZPolicyStruct *self;

  g_assert(type > Z_PST_NONE && type < Z_PST_MAX);
  self = PyObject_New(ZPolicyStruct, &z_policy_struct_types[type]);

  if (!self)
    return NULL;

  self->dict = dict;
  self->format_func = NULL;
  self->is_config = FALSE;
  z_policy_dict_wrap(dict, (ZPolicyObj *) self);

  return (ZPolicyObj *) self;
}

static void
z_policy_struct_free(ZPolicyObj *s)
{
  ZPolicyStruct *self = (ZPolicyStruct *) s;

  if (self->dict)
    {
      z_policy_dict_unwrap(self->dict, s);
      z_policy_dict_destroy(self->dict);
    }
  PyObject_Del(self);
}

void
z_policy_struct_module_init(void)
{
  static struct {
    gchar *name;
    gint parent_type;
  } types[] =
  {
    { "Unknown" , -1 },                      /* Z_PST_NONE */
    { "Shared", -1 },                        /* Z_PST_SHARED */
    { "SockAddr", -1 },                      /* Z_PST_SOCKADDR */
    { "SockAddrInet", Z_PST_SOCKADDR },      /* Z_PST_SOCKADDR_INET */
    { "SockAddrInet6", Z_PST_SOCKADDR },     /* Z_PST_SOCKADDR_INET6 */
    { "SockAddrUnix", Z_PST_SOCKADDR },      /* Z_PST_SOCKADDR_UNIX */
    { "DispatchBind", -1 },                  /* Z_PST_DISPATCH_BIND */
    { "DBSockAddr", Z_PST_DISPATCH_BIND },   /*Z_PST_DB_SOCKADDR */
    { "DBIface", Z_PST_DISPATCH_BIND },      /* Z_PST_DB_IFACE */
    { "DBIfaceGroup", Z_PST_DISPATCH_BIND }, /* Z_PST_DB_IFACE_GROUP */
    { "ProxyGroup", -1 },                    /* Z_PST_PROXY_GROUP */
  };
  ZPolicyObj *m;
  gint i;

  m = PyImport_AddModule("Zorp.Zorp");

  for (i = Z_PST_NONE + 1; i < Z_PST_MAX; i++)
    {
      gchar type_ref[64];
      PyTypeObject *py_type_object;
      ZPolicyObj *policy_object;

      g_assert(types[i].name);

     if (!z_policy_struct_types[i].tp_repr)
        {
          memcpy(&z_policy_struct_types[i], &z_policy_struct_types[Z_PST_NONE], sizeof(z_policy_struct_types[Z_PST_NONE]));
          z_policy_struct_types[i].tp_name = types[i].name;
          z_policy_struct_types[i].tp_doc = types[i].name;
          if (types[i].parent_type != -1)
            {
              py_type_object = &z_policy_struct_types[types[i].parent_type];
              policy_object = (ZPolicyObj *) py_type_object;
              z_policy_var_ref(policy_object);
              z_policy_struct_types[i].tp_base = &z_policy_struct_types[types[i].parent_type];
            }
        }
      PyType_Ready(&z_policy_struct_types[i]);
      py_type_object = &z_policy_struct_types[i];
      policy_object = (ZPolicyObj *) py_type_object;
      Py_INCREF(policy_object);

      g_snprintf(type_ref, sizeof(type_ref), "%sType", types[i].name);
      PyModule_AddObject(m, type_ref, (ZPolicyObj *) &z_policy_struct_types[i]);
    }
}

PyTypeObject z_policy_struct_types[Z_PST_MAX] =
{
  {
    /* used as a template type for other types */
    PyObject_HEAD_INIT(&PyType_Type)

    0,                                      /* ob_size */
    "ZPolicyStruct",                        /* tp_name */
    sizeof(ZPolicyStruct),                  /* tp_basicsize */
    0,                                      /* tp_itemsize */
    (destructor)z_policy_struct_free,       /* tp_dealloc */
    NULL,                                   /* tp_print */
    (getattrfunc) z_policy_struct_getattr,  /* tp_getattr */
    (setattrfunc) z_policy_struct_setattr,  /* tp_setattr */
    NULL,                                   /* tp_compare */
    z_policy_struct_str,                    /* tp_repr */
    NULL,                                   /* tp_as_number */
    NULL,                                   /* tp_as_sequence */
    NULL,                                   /* tp_as_mapping */
    NULL,                                   /* tp_hash */
    NULL,                                   /* tp_call */
    z_policy_struct_str,                    /* tp_str */
    NULL,                                   /* tp_getattro */
    NULL,                                   /* tp_setattro */
    NULL,                                   /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /* tp_flags */
    "ZPolicyProxy class",                   /* tp_doc */
    NULL,                                   /* tp_traverse */
    NULL,                                   /* tp_clear */
    NULL,                                   /* tp_reachcompare */
    0,                                      /* tp_weaklistoffset */
    NULL,                                   /* tp_iter */
    NULL,                                   /* tp_iternext */
    NULL,                                   /* tp_methods */
    NULL,                                   /* tp_members */
    NULL,                                   /* tp_getset */
    NULL,                                   /* tp_base */
    NULL,                                   /* tp_dict */
    NULL,                                   /* tp_descr_get */
    NULL,                                   /* tp_descr_set */
    0,                                      /* tp_dictoffset */
    NULL,                                   /* tp_init */
    NULL,                                   /* tp_alloc */
    PyType_GenericNew,                      /* tp_new */
    NULL,                                   /* tp_free */
    NULL,                                   /* tp_is_gc */
    NULL,                                   /* tp_bases */
    NULL,                                   /* tp_mro */
    NULL,                                   /* tp_cache */
    NULL,                                   /* tp_subclasses */
    NULL,                                   /* tp_weaklist */
    NULL,                                   /* tp_del */
    0,                                      /* tp_version_tag */
  }
};
