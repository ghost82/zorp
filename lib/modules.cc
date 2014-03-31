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

#include <zorp/zorp.h>
#include <zorp/log.h>
#include <gmodule.h>

#define G_MODULE_ERROR_SAFE() (g_module_error() ? g_module_error() : "(null)")
#define ZORP_MODULE_INIT_NAME "_Z16zorp_module_initv"

/**
 * Load a Zorp module.
 *
 * @param modname name of the module to load
 *
 * This function opens the module specified by modname as a shared object
 * and initializes it by calling its zorp_module_init function.
 *
 * @return TRUE on success
 **/
gint
z_load_module(gchar *modname)
{
  GModule *m;
  gchar *buf;
  gint (*modinit)(void) __attribute__((may_alias));

  z_enter();
  buf = g_module_build_path(ZORP_LIBDIR, modname);
  m = g_module_open(buf, static_cast<GModuleFlags>(0));
  if (m &&
      g_module_symbol(m, ZORP_MODULE_INIT_NAME, (gpointer *) &modinit) &&
      modinit())
    {
      /*LOG
        This message serves informational purposes, and indicates that
        the given module was successfully loaded from the given shared
        object.
       */
      z_log(NULL, CORE_DEBUG, 8, "Module successfully loaded; module='%s', file='%s'", modname, buf);
      g_free(buf);
      z_return(TRUE);
    }

  /*LOG
    This message indicates that loading a proxy module failed.
   */
  z_log(NULL, CORE_ERROR, 1, "Module loading failed; module='%s', file='%s', error='%s'", modname, buf, G_MODULE_ERROR_SAFE());
  g_free(buf);
  z_return(FALSE);
}
