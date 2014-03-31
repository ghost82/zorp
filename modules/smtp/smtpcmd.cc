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
 * Author:  Attila SZALAY <sasa@balabit.hu>
 * Auditor:
 * Last audited version:
 * Notes:
 *
 ***************************************************************************/

#include "smtp.h"

#include <zorp/log.h>
#include <zorp/misc.h>

#include <string.h>

#define FROM_ADDR "From:"
#define TO_ADDR   "To:"

/**
 * smtp_parse_atom:
 * @self: SmtpProxy instance
 * @path: forward or reverse path to parse
 * @end: the character where the parsing ended
 *
 * This function parses an 'atom' as defined by RFC821. The return value
 * indicates whether parsing succeeded, thus it always returns TRUE (as an
 * atom can be 0 characters in length).
 **/
static gboolean
smtp_parse_atom(SmtpProxy *self G_GNUC_UNUSED, gchar *path, gchar **end)
{
  /* characters excluded from <c> in RFC821, that is, members of <special> and <SP> */
  static const gchar specials[] = { '(', ')', '<', '>', '@', ',', ';', ':', '\\', '"', '.', '[', ']', ' ', '\0' };

  z_proxy_enter(self);

  size_t num_of_ordinary_chars = strcspn(path, specials);
  *end = path + num_of_ordinary_chars;

  z_proxy_leave(self);
  return TRUE;
}

/**
 * smtp_parse_domain:
 * @self: SmtpProxy instance
 * @path: forward or reverse path to parse
 * @end: the character where the parsing ended
 *
 * This function parses a 'domain' as defined by RFC821. The return value
 * indicates whether parsing succeeded. Regardless of the return value @end
 * is filled with the character position where parsing ended.
 **/
static gboolean
smtp_parse_domain(SmtpProxy *self, gchar *path, gchar **end)
{
  gchar *src;

  z_proxy_enter(self);
  if (path[0] == '#')
    {
      IGNORE_UNUSED_RESULT(strtol(&path[1], &src, 10));
      *end = src;
    }
  else if (path[0] == '[')
    {
      /* check domain-literal */
      src = path + 1;
      while (*src)
        {
          if (*src == ']')
            {
              break;
            }
          else if (*src == '"' || *src == '\n')
            {
              return FALSE;
            }
          else if (*src == '\\')
            {
              src++;
            }

          src++;
        }
      *end = src + 1;
    }
  else
    {
      src = path;
      while (*src)
        {
          if (!smtp_parse_atom(self, src, &src) ||
              *src != '.')
            {
              break;
            }
          src++;
        }
      *end = src;
    }
  z_proxy_leave(self);
  return src != path;
}

/**
 * smtp_parse_source_route:
 * @self: SmtpProxy instance
 * @path: forward or reverse path to parse
 * @end: the character where the parsing ended
 *
 * This function parses a 'source-route' as defined by RFC821. The return value
 * indicates whether parsing succeeded. Regardless of the return value @end
 * is filled with the character position where parsing ended.
 **/
static gboolean
smtp_parse_source_route(SmtpProxy *self, gchar *path, gchar **end)
{
  gchar *src, *p;
  gboolean continued = FALSE;

  z_proxy_enter(self);
  /* Source route format: @fqdn,fqdn,fqdn: */

  src = path;
  *end = src;
  /* source route present */
  while (*src == '@')
    {
      src++;
      continued = FALSE;
      if (!smtp_parse_domain(self, src, &p))
        {
          z_proxy_leave(self);
          return FALSE;
        }
      if (*p != ',' && *p != ':')
        {
          z_proxy_leave(self);
          return FALSE;
        }
      src = p + 1;
      *end = src;
      if (*p == ':')
        {
          break;
        }
      continued = TRUE;
    }

  z_proxy_leave(self);
  return !continued;
}

/**
 * smtp_parse_source_route:
 * @self: SmtpProxy instance
 * @path: forward or reverse path to parse
 * @end: the character where the parsing ended
 *
 * This function parses a 'local-part' as defined by RFC821. The return value
 * indicates whether parsing succeeded. Regardless of the return value @end
 * is filled with the character position where parsing ended.
 **/
static gboolean
smtp_parse_local_part(SmtpProxy *self, gchar *path, gchar **end)
{
  gchar *src;

  z_proxy_enter(self);
  src = path;
  if (*src == '"')
    {
      /* quoted local part */

      src = path + 1;
      while (*src)
        {
          if (*src == '"')
            {
              break;
            }
          else if (*src == '\\')
            {
              src++;
            }

          src++;
        }
      *end = src + 1;
    }
  else
    {
      /* *atom */
      while (*src)
        {
          if (!smtp_parse_atom(self, src, &src) || *src != '.')
            {
              break;
            }
          src++;
        }
      *end = src;
    }
  z_proxy_leave(self);
  return src != path;
}

/**
 * smtp_parse_source_route:
 * @self: SmtpProxy instance
 * @result: the function stores the plain email address here
 * @path: forward or reverse path to parse
 * @end: the character where the parsing ended
 *
 * This function parses an 'address' as defined by RFC821. The return value
 * indicates whether parsing succeeded. Regardless of the return value @end
 * is filled with the character position where parsing ended. If the parsing
 * was successful the address string is stored in the argument @result.
 **/
static gboolean
smtp_parse_address(SmtpProxy *self, GString *result, gchar *path, gchar **end)
{
  gchar *src = path;
  gchar *start;

  z_proxy_enter(self);
  start = src;
  *end = src;
  if (!smtp_parse_local_part(self, src, end))
    {
      /*LOG
        This message indicates that parsing the local part of the address failed.
       */
      z_proxy_log(self, SMTP_VIOLATION, 2, "Error parsing local part; path='%s'", path);
      z_proxy_leave(self);
      return FALSE;
    }
  src = *end;
  if (*src != '@')
    {
      if (self->append_domain->len)
        {
          g_string_assign_len(result, start, (*end) - start);
          g_string_sprintfa(result, "@%s", self->append_domain->str);
        }
      else
        {
	  /*LOG
	    This message indicates that the local part of the mail is invalid because it does
	    not end with a '@' sign.
	   */
          z_proxy_log(self, SMTP_VIOLATION, 2, "Local part does not end in '@'; path='%s'", path);
          z_proxy_leave(self);
          return FALSE;
        }
      z_proxy_leave(self);
      return TRUE;
    }
  src++;
  *end = src;
  if (!smtp_parse_domain(self, src, end))
    {
      /*LOG
        This message indicates that the domain name of the mail is invalid.
       */
      z_proxy_log(self, SMTP_VIOLATION, 2, "Invalid domain name in path; path='%s'", path);
      z_proxy_leave(self);
      return FALSE;
    }
  g_string_assign_len(result, start, (*end) - start);
  z_proxy_leave(self);
  return TRUE;
}

/**
 * smtp_sanitize_address:
 * @result: copy the stripped down e-mail address to this string
 * @path: forward- or reversepath in SMTP sense (the argument to RCPT To: or MAIL From)
 * @end: the address of the character where processing ended is stored here
 *
 * This function is used to strip unneeded source routing information
 * from reverse- or forward paths. While stripping the unnecessary
 * bits, the function also validates the incoming string. The argument
 * @end is useful when SMTP extensions are used, as the set extensions
 * are starting where @end points to. If @end is NULL, then no trailing
 * characters are permitted.
 *
 * Returns: TRUE to indicate success
 **/
gboolean
smtp_sanitize_address(SmtpProxy *self, GString *result, gchar *path, gboolean empty_path_ok, gchar **final_end)
{
  gchar *src, *end;
  gboolean res;
  gboolean unbracketed = FALSE;

  z_proxy_enter(self);
  src = path;
  /* skip spaces */
  while (*src == ' ')
    src++;

  if (*src != '<' )
    {
      unbracketed = TRUE;
      if (!self->permit_omission_of_angle_brackets)
        {
          /*LOG
            This message indicates that the address path is invalid because it does not start with
            a '<' sign.
           */
          z_proxy_log(self, SMTP_VIOLATION, 2, "Path does not start with '<'; path='%s'", path);
          z_proxy_return(self, FALSE);
        }
    }
  else
    {
      src++;    /* skip over the < */
    }

  g_string_truncate(result, 0);
  if (!smtp_parse_source_route(self, src, &end) && src != end)
    {
      /*LOG
        This message indicates that the source-root information of the address patch is invalid.
       */
      z_proxy_log(self, SMTP_VIOLATION, 2, "Invalid source route information; path='%s'", path);
      z_proxy_return(self, FALSE);
    }
  src = end;
  if (*src != '>' || !empty_path_ok)
    {
      if (!smtp_parse_address(self, result, src, &end))
        {
	  /*LOG
	    This message indicates that the address information is invalid.
	   */
          z_proxy_log(self, SMTP_VIOLATION, 2, "Invalid address information; path='%s'", path);
          z_proxy_return(self, FALSE);
        }
    }
  src = end;

  if (unbracketed)
    {
      if (*src == '>')
        {
          /*LOG
            This message indicates that the address path is invalid because it does not start with
            a '>' sign but ends with it.
            */
          z_proxy_log(self, SMTP_VIOLATION, 2, "Path does not begin with '<' but ends with '>'; path='%s'", path);
          z_proxy_return(self, FALSE);
        }
    }
  else
    {
      if (*src == '>')
        {
          src++;
        }
      else
        {
          /*LOG
            This message indicates that the address path is invalid because it does not end with
            a '>' sign.
            */
          z_proxy_log(self, SMTP_VIOLATION, 2, "Path begins with '<' but does not end with '>'; path='%s'", path);
          z_proxy_return(self, FALSE);
        }
    }

  if (final_end)
    {
      *final_end = src;
      res = TRUE;
    }
  else
    {
      res = (*src == 0);
    }
  z_proxy_return(self, res);
}

/**
 * smtp_is_domain:
 * @self: SmtpProxy instance
 * @domain: domain to check
 *
 * This function checks whether the argument is a valid domain name.
 *
 * Returns: TRUE to indicate success
 **/
static gboolean
smtp_is_domain(SmtpProxy *self, gchar *domain)
{
  gchar *end;

  if (smtp_parse_domain(self, domain, &end) && *end == '\0')
    return TRUE;
  return FALSE;
}

/**
 * smtp_is_queue_tag:
 * @self: SmtpProxy instance
 * @tag: tag to verify
 *
 * This function validates an SMTP queue tag when the '#' form of ETRN is
 * used.
 *
 * Returns: TRUE to indicate success
 **/
static gboolean
smtp_is_queue_tag(SmtpProxy *self G_GNUC_UNUSED, gchar *tag)
{
  gchar *p = tag;
  while (*p)
    {
      if (!(isalpha(*p) || *p == '-' || (*p >= '0' && *p <= '9') || *p == '.' || *p == '_'))
        return FALSE;
      p++;
    }
  return TRUE;
}

/**
 * smtp_is_xtext: self: SmtpProxy instance xtext: tag to verify
 *
 * This function validates an SMTP xtext, which is a string consisting of
 * characters in the range [33-126] inclusive, other characters are encoded
 * using two hexadecimal characters.
 *
 * Returns: TRUE to indicate success
 **/
static gboolean
smtp_is_xtext(SmtpProxy *self G_GNUC_UNUSED, gchar *xtext)
{
  const guchar *p = (const guchar *) xtext;

  while (*p)
    {
      if (*p < 33 || *p > 126 || *p == '=')
        return FALSE;
      else if (*p == '+')
        {
          /* hexadecimal encoding */
          if (!(*(p+1)) || !(*(p+2)) || !isxdigit(*(p+1)) || !isxdigit(*(p+2)))
            return FALSE;
          p += 2;
        }
      p++;
    }
  return TRUE;
}

/**
 * smtp_parse_mail_extensions:
 * @self: SmtpProxy instance
 * @ext: MAIL extensions
 *
 * This function is called when the MAIL command contains extensions that
 * need to be parsed. Currently the only such extension is SIZE, everything else
 * causes an error.
 *
 * Returns: TRUE to indicate success
 **/
static gboolean
smtp_parse_mail_extensions(SmtpProxy *self, gchar *ext, GString *forward_extensions)
{
  gchar *p;
  gchar kw[32], val[256];
  guint kw_len, val_len;

  z_proxy_enter(self);
  g_string_truncate(forward_extensions, 0);
  p = ext;
  while (*p == ' ')
    p++;
  while (*p)
    {
      /* skip whitespace */
      kw_len = 0;
      while ((isalpha(*p) || isdigit(*p)) && kw_len < sizeof(kw) - 1)
        {
          kw[kw_len++] = *p;
          p++;
        }
      kw[kw_len] = 0;

      if (*p != '=')
        z_proxy_return(self, FALSE);
      p++;
      val_len = 0;
      while (p && *p != ' ' && *p != '=' && *p > 32 && *p < 127 && val_len < sizeof(val) - 1)
        {
          val[val_len++] = *p;
          p++;
        }
      val[val_len] = 0;

      if ((self->active_extensions & SMTP_EM_SIZE) && strcasecmp(kw, "SIZE") == 0)
        {
          gchar *end;
          gulong size;

          size = strtol(val, &end, 10);
          if (*end != 0)
            {
	      /*LOG
	        This message indicates that the SIZE extension of the MAIL command is invalid
		because it must contain non-numeric characters. Zorp rejects the request.
	       */
              z_proxy_log(self, SMTP_VIOLATION, 2, "Invalid SIZE extension in the MAIL command; extensions='%s'", ext);
              z_proxy_return(self, FALSE);
            }
          g_string_sprintfa(forward_extensions, "SIZE=%lu ", size);
        }
      else if ((self->active_extensions & SMTP_EM_8BITMIME) && strcasecmp(kw, "BODY") == 0)
        {
          if (strcasecmp(val, "7BIT") != 0 && strcasecmp(val, "8BITMIME") != 0)
            {
	      /*LOG
	        This message indicates that the BODY extension of the MAIL command is invalid
		because it must contain either '7BIT' or '8BITMIME'. Zorp rejects the request.
	       */
              z_proxy_log(self, SMTP_VIOLATION, 2, "Invalid BODY extension in the MAIL command; extensions='%s'", ext);
              z_proxy_return(self, FALSE);
            }
          g_string_sprintfa(forward_extensions, "BODY=%s ", val);
        }
      else if ((self->active_extensions & SMTP_EM_AUTH) && strcasecmp(kw, "AUTH") == 0)
        {
          if (!smtp_is_xtext(self, val))
            {
	      /*LOG
	        This message indicates that the AUTH extension of the MAIL command is invalid
		because it must be xtext. Zorp rejects the request.
	       */
              z_proxy_log(self, SMTP_VIOLATION, 2, "Invalid AUTH sender, not an xtext; extensions='%s'", ext);
              z_proxy_return(self, FALSE);
            }
          g_string_sprintfa(forward_extensions, "AUTH=%s ", val);
        }
      else
        {
	  /*LOG
	    This message indicates that the given extension is invalid with the MAIL command and Zorp
	    rejects the request.
	   */
          z_proxy_log(self, SMTP_VIOLATION, 2, "Invalid extension in the MAIL command; extensions='%s'", ext);
          z_proxy_return(self, FALSE);
        }

      while (*p == ' ')
        p++;
    }
  /* strip trailing spaces */
  p = forward_extensions->str + forward_extensions->len - 1;
  while (p > forward_extensions->str && *p == ' ')
    {
      *p = '\0';
      p--;
      forward_extensions->len--;
    }
  z_proxy_return(self, TRUE);
}

SmtpRequestTypes
smtp_request_EHLO(SmtpProxy *self)
{
  g_string_assign(self->helo_string, self->request_param->str);
  g_string_assign(self->protocol, strcmp(self->request->str, "HELO") ? "ESMTP" : "SMTP");

  return smtp_is_domain(self, self->request_param->str) ? SMTP_REQ_ACCEPT : SMTP_REQ_REJECT;
}

SmtpResponseTypes
smtp_response_EHLO(SmtpProxy *self)
{
  self->active_extensions = static_cast<SmtpActionTypes>(0);

  if (self->response_lines && strcmp(self->request->str, "HELO") == 0)
    {
      /* extended response for a HELO */
      return SMTP_RSP_REJECT;
    }
  else if (self->response_lines)
    {
      GList *p, *pnext;

      for (p = self->response_lines; p; p = pnext)
        {
          gchar token[256], *dst = token;
          const gchar *src;
          gboolean remove_ext_from_list = TRUE;
          SmtpExtensionDesc *ext;

          for (src = ((GString *) p->data)->str;
               (dst - token) < (gint) sizeof(token) - 1 && isalnum(*src);
               src++, dst++)
            {
              /* make extension id upper case */
              *dst = toupper(*src);
            }
          *dst = 0;
          pnext = p->next;

          if (smtp_policy_is_extension_permitted(self, token))
            {
              remove_ext_from_list = FALSE;

              ext = static_cast<SmtpExtensionDesc *>(g_hash_table_lookup(known_extensions, token));
              if (ext)
                {
                  /* this is a known extension */
                  self->active_extensions |= ext->extension_mask;

                  if (ext->extension_mask & SMTP_EM_STARTTLS)
                    {
                      /* we also have some hard-coded rules depending on SSL settings:
                       *  - client: != ACCEPT_STARTTLS / server *: we have to remove 'STARTTLS'
                       *  - client: ACCEPT_STARTTLS / server != FORWARD_STARTTLS: we have to add 'STARTTLS'
                       */
                      if (self->super.ssl_opts.security[EP_CLIENT] != PROXY_SSL_SEC_ACCEPT_STARTTLS ||
                          self->start_tls_ok[EP_CLIENT])
                        {
                          self->active_extensions &= ~SMTP_EM_STARTTLS;
                          remove_ext_from_list = TRUE;
                        }
                      else if (self->super.ssl_opts.security[EP_CLIENT] == PROXY_SSL_SEC_ACCEPT_STARTTLS &&
                               self->super.ssl_opts.security[EP_SERVER] != PROXY_SSL_SEC_FORWARD_STARTTLS &&
                               !self->start_tls_ok[EP_CLIENT])
                        {
                          self->active_extensions |= SMTP_EM_STARTTLS;
                        }
                    }
                }
            }

          if (remove_ext_from_list)
            {
              /* not permitted extension */
              g_string_free((GString *) p->data, TRUE);
              self->response_lines = g_list_remove_link(self->response_lines, p);
              g_list_free_1(p);
            }
        }
    }

  if (self->response->str[0] == '2')
    {
      self->smtp_state = SMTP_STATE_EHLO;
    }
  return SMTP_RSP_ACCEPT;
}

SmtpRequestTypes
smtp_request_AUTH(SmtpProxy *self)
{
  SmtpRequestTypes res = SMTP_REQ_REJECT;

  z_proxy_enter(self);
  if (self->active_extensions & SMTP_EM_AUTH)
    res = SMTP_REQ_ACCEPT;
  z_proxy_return(self, res);
}

SmtpResponseTypes
smtp_response_AUTH(SmtpProxy *self)
{
  SmtpResponseTypes res = SMTP_RSP_ACCEPT;

  if (strcmp(self->response->str, "334") == 0)
    self->smtp_state = SMTP_STATE_AUTH;
  else if (strcmp(self->response->str, "235") == 0)
    self->smtp_state = SMTP_STATE_EHLO; /* authentication was successful, go on receiving mail */
  else if (self->response->str[0] == '4' || self->response->str[0] == '5')
    self->smtp_state = SMTP_STATE_EHLO; /* authentication was aborted, return to normal state */
  else
    res = SMTP_RSP_REJECT;
  return res;
}

SmtpRequestTypes
smtp_request_MAIL(SmtpProxy *self)
{
  GString *sanitized_address, *forward_extensions = NULL;
  gchar *end;

  z_proxy_enter(self);
  if (g_ascii_strncasecmp(self->request_param->str, FROM_ADDR, strlen(FROM_ADDR)) == 0)
    {
      sanitized_address = g_string_sized_new(128);
      if (smtp_sanitize_address(self, sanitized_address, &self->request_param->str[strlen(FROM_ADDR)], TRUE, &end))
        {
          if (*end)
            forward_extensions = g_string_sized_new(strlen(end) + 1);
          if (*end == 0 || smtp_parse_mail_extensions(self, end, forward_extensions))
            {
              g_string_sprintf(self->request_param, "%s<%s>%s%s",
                               FROM_ADDR, sanitized_address->str,
                               forward_extensions ? " " : "",
                               forward_extensions ? forward_extensions->str : "");
              g_string_assign(self->sender, sanitized_address->str);
              g_string_free(sanitized_address, TRUE);
              if (forward_extensions)
                g_string_free(forward_extensions, TRUE);
              z_proxy_return(self, SMTP_REQ_ACCEPT);
            }
          if (forward_extensions)
            g_string_free(forward_extensions, TRUE);
        }
      g_string_free(sanitized_address, TRUE);
    }
  z_proxy_return(self, SMTP_REQ_REJECT);
}

SmtpResponseTypes
smtp_response_MAIL(SmtpProxy *self)
{
  if (self->response->str[0] == '2')
    {
      self->smtp_state = SMTP_STATE_MAIL_FROM;
      z_proxy_log(self, SMTP_INFO, 4, "Server accepted the sender; sender='%s', response='%s', response_param='%s'", self->sender->str, self->response->str, self->response_param->str);
    }
  else if (self->response->str[0] == '4' || self->response->str[0] == '5')
    {
      z_proxy_log(self, SMTP_ERROR, 3, "Server rejected the sender; sender='%s', response='%s', response_param='%s'", self->sender->str, self->response->str, self->response_param->str);
    }
  return SMTP_RSP_ACCEPT;
}

SmtpRequestTypes
smtp_request_RCPT(SmtpProxy *self)
{
  z_proxy_enter(self);
  if (g_ascii_strncasecmp(self->request_param->str, TO_ADDR, strlen(TO_ADDR)) == 0)
    {
      if (smtp_sanitize_address(self, self->sanitized_recipient, &self->request_param->str[strlen(TO_ADDR)], FALSE, NULL))
        {
          g_string_sprintf(self->request_param, "%s<%s>", TO_ADDR, self->sanitized_recipient->str);
          z_proxy_return(self, SMTP_REQ_ACCEPT);
        }
    }
  z_proxy_return(self, SMTP_REQ_REJECT);
}

SmtpResponseTypes
smtp_response_RCPT(SmtpProxy *self)
{
  if (self->response->str[0] == '2')
    {
      if (self->recipients->len)
        g_string_sprintfa(self->recipients, " %s", self->sanitized_recipient->str);
      else
        g_string_append(self->recipients, self->sanitized_recipient->str);
      self->smtp_state = SMTP_STATE_RCPT_TO;
      z_proxy_log(self, SMTP_INFO, 4, "Server accepted the recipient; recipient='%s', response='%s', response_param='%s'", self->sanitized_recipient->str, self->response->str, self->response_param->str);
    }
  else if (self->response->str[0] == '4' || self->response->str[0] == '5')
    {
      z_proxy_log(self, SMTP_ERROR, 3, "Server rejected the recipient; recipient='%s', response='%s', response_param='%s'", self->sanitized_recipient->str, self->response->str, self->response_param->str);
    }
  return SMTP_RSP_ACCEPT;
}

SmtpRequestTypes
smtp_request_ETRN(SmtpProxy *self)
{
  if (self->active_extensions & SMTP_EM_ETRN && self->request_param->len > 0)
    {
      gchar *p = self->request_param->str;
      if (self->request_param->str[0] == '@')
        {
          /* domain name with subdomains */
          if (smtp_is_domain(self, p+1))
            return SMTP_REQ_ACCEPT;
        }
      else if (self->request_param->str[0] == '#')
        {
          /* queue tag */
          if (smtp_is_queue_tag(self, p+1))
            return SMTP_REQ_ACCEPT;
        }
      else
        {
          /* fqdn */
          if (smtp_is_domain(self, p))
            return SMTP_REQ_ACCEPT;
        }
    }
  return SMTP_REQ_REJECT;
}

SmtpResponseTypes
smtp_response_RSET(SmtpProxy *self)
{
  z_proxy_enter(self);
  if (self->response->str[0] == '2')
    smtp_reset_state(self);
  z_proxy_return(self, SMTP_RSP_ACCEPT);
}

SmtpRequestTypes
smtp_request_DATA(SmtpProxy *self)
{
  z_proxy_enter(self);
  self->data_transfer = TRUE;
#if 0
  if (self->response->str[0] == '3')
    self->data_transfer = TRUE;
  else if (self->response->str[0] == '2')
    self->smtp_state = SMTP_STATE_EHLO;
#endif
  z_proxy_return(self, SMTP_REQ_ACCEPT);
}

SmtpRequestTypes
smtp_request_general_noarg(SmtpProxy *self)
{
  SmtpRequestTypes res;

  z_proxy_enter(self);
  res = self->request_param->len == 0 ? SMTP_REQ_ACCEPT : SMTP_REQ_REJECT;
  z_proxy_return(self, res);
}

SmtpResponseTypes
smtp_response_QUIT(SmtpProxy *self)
{
  self->smtp_state = SMTP_STATE_QUIT;
  return SMTP_RSP_ACCEPT;
}

static SmtpRequestTypes
smtp_request_STARTTLS(SmtpProxy *self)
{
  z_proxy_enter(self);

  if (smtp_request_general_noarg(self) != SMTP_REQ_ACCEPT)
    goto error;

  if ((self->active_extensions & SMTP_EM_STARTTLS) == 0)
    {
      z_proxy_log(self, SMTP_VIOLATION, 4, "Server does not support the STARTTLS extension;");
      goto error;
    }

  if (self->start_tls_ok[EP_CLIENT] == TRUE)
    {
      z_proxy_log(self, SMTP_VIOLATION, 3, "STARTTLS command is allowed only in plain-text mode;");
      goto error;
    }

  /* based on the client/server SSL settings, we do the following:
   *  - client ACCEPT_STARTTLS / server FORWARD_STARTTLS: we forward
   *    the request as it is
   *  - client !ACCEPT_STARTTLS / server *: we reject the request
   *  - client ACCEPT_STARTTLS / server !FORWARD_STARTTLS: return success
   *    to the client and don't forward the request
   */
  switch (self->super.ssl_opts.security[EP_CLIENT])
    {
    case PROXY_SSL_SEC_FORWARD_STARTTLS:
      g_assert_not_reached();

    case PROXY_SSL_SEC_NONE:
      z_proxy_log(self, SMTP_POLICY, 4, "Client-side STARTTLS is not permitted by policy;");
      goto error;

    case PROXY_SSL_SEC_FORCE_SSL:
      SMTP_SET_RESPONSE(SMTP_MSG_TLS_NOT_AVAILABLE);
      goto error;

    case PROXY_SSL_SEC_ACCEPT_STARTTLS:
      switch (self->super.ssl_opts.security[EP_SERVER])
        {
        case PROXY_SSL_SEC_ACCEPT_STARTTLS:
          g_assert_not_reached();

        case PROXY_SSL_SEC_FORWARD_STARTTLS:
          break;

        case PROXY_SSL_SEC_NONE:
        case PROXY_SSL_SEC_FORCE_SSL:
          /* Nothing to do. SSL handshake made as action */
          break;
        }
      break;
    }

  z_proxy_return(self, SMTP_REQ_ACCEPT);

error:
  z_proxy_return(self, SMTP_REQ_REJECT);
}

static SmtpResponseTypes
smtp_response_STARTTLS(SmtpProxy *self)
{
  z_proxy_enter(self);

  /* we can get here only in the following case, all others should have been handled in
   * parser of the starttls command
   *  - client ACCEPT_STARTTLS / server FORWARD_STARTTLS: do handshake on both
   *    sides if the server accepted the request
   */
  g_assert((self->super.ssl_opts.security[EP_CLIENT] == PROXY_SSL_SEC_ACCEPT_STARTTLS) &&
           (self->super.ssl_opts.security[EP_SERVER] == PROXY_SSL_SEC_FORWARD_STARTTLS));

  if (atoi(self->response->str) != 220)
    z_proxy_return(self, SMTP_RSP_ACCEPT);

  z_proxy_log(self, SMTP_INFO, 3, "Server accepted STARTTLS request, starting handshake;");

  if (!smtp_copy_response(self))
    goto error;

  if (self->tls_passthrough)
    {
      /* Fall-back to plug requested, do not start handshake but
         transition to the PLUG state */
      z_proxy_log(self, SMTP_INFO, 3, "STARTTLS accepted by server, switching to plug mode;");
      self->proxy_state = SMTP_PROXY_PLUG;
    }
  else
    {
      /* Do server and client handshake */
      if (!z_proxy_ssl_request_handshake(&self->super, EP_SERVER, FALSE))
        {
          z_proxy_log(self, SMTP_ERROR, 2, "Server-side SSL handshake failed, terminating session;");
          goto error;
        }

      if (!z_proxy_ssl_request_handshake(&self->super, EP_CLIENT, FALSE))
        {
          z_proxy_log(self, SMTP_ERROR, 2, "Client-side SSL handshake failed, terminating session;");
          goto error;
        }

      self->start_tls_ok[EP_CLIENT] = self->start_tls_ok[EP_SERVER] = TRUE;

      /* go back to the initial state, so that we force the client to
         do a HELO/EHLO again before doing anything else */
      self->smtp_state = SMTP_STATE_INITIAL;
    }

  /* We've already copied the response to the client, so instead of
     returning SMTP_RSP_ACCEPT we return _NOOP to signal that the
     response must not be copied again. */
  z_proxy_return(self, SMTP_RSP_NOOP);

error:
  self->smtp_state = SMTP_STATE_QUIT;
  z_proxy_return(self, SMTP_RSP_NOOP);
}

static SmtpRequestTypes
smtp_action_STARTTLS(SmtpProxy *self)
{
  SmtpRequestTypes res = SMTP_REQ_ACCEPT;

  z_proxy_enter(self);

  switch (self->super.ssl_opts.security[EP_SERVER])
    {
    case PROXY_SSL_SEC_ACCEPT_STARTTLS:
      g_assert_not_reached();

    case PROXY_SSL_SEC_FORWARD_STARTTLS:
      break;

    case PROXY_SSL_SEC_NONE:
    case PROXY_SSL_SEC_FORCE_SSL:
      /* return success to the client right away */
      z_proxy_log(self, SMTP_INFO, 3, "Zorp is configured for client-only SMTP STARTTLS, accepting request;");

      SMTP_SET_RESPONSE(SMTP_MSG_READY_TO_STARTTLS);

      if (!smtp_copy_response(self))
        goto error;

      if (!z_proxy_ssl_request_handshake(&self->super, EP_CLIENT, FALSE))
        {
          z_proxy_log(self, SMTP_ERROR, 2, "Client-side SSL handshake failed, terminating session;");
          self->start_tls_ok[EP_CLIENT] = FALSE;
          self->smtp_state = SMTP_STATE_QUIT;
          res = SMTP_REQ_NOOP;
        }
      else
        {
          self->start_tls_ok[EP_CLIENT] = TRUE;
          res = SMTP_REQ_NOOP;
        }

      break;
    }

  z_proxy_return(self, res);

error:
  self->smtp_state = SMTP_STATE_QUIT;
  z_proxy_return(self, SMTP_REQ_REJECT);
}

static struct _SmtpCommandDesc known_commands_table[] =
{
  { "HELO",     smtp_request_EHLO,          smtp_response_EHLO,     NULL,                 SMTP_STATE_INITIAL | SMTP_STATE_EHLO },
  { "EHLO",     smtp_request_EHLO,          smtp_response_EHLO,     NULL,                 SMTP_STATE_INITIAL | SMTP_STATE_EHLO },
  { "MAIL",     smtp_request_MAIL,          smtp_response_MAIL,     NULL,                 SMTP_STATE_EHLO },
  { "RCPT",     smtp_request_RCPT,          smtp_response_RCPT,     NULL,                 SMTP_STATE_MAIL_FROM | SMTP_STATE_RCPT_TO },
  { "DATA",     smtp_request_DATA,          NULL,                   NULL,                 SMTP_STATE_RCPT_TO },
  { "ETRN",     smtp_request_ETRN,          NULL,                   NULL,                 SMTP_STATE_EHLO },
  { "AUTH",     smtp_request_AUTH,          smtp_response_AUTH,     NULL,                 SMTP_STATE_EHLO },
  { "RSET",     smtp_request_general_noarg, smtp_response_RSET,     NULL,                 SMTP_STATE_INITIAL | SMTP_STATE_EHLO | SMTP_STATE_MAIL_FROM | SMTP_STATE_RCPT_TO | SMTP_STATE_DATA },
  { "QUIT",     smtp_request_general_noarg, smtp_response_QUIT,     NULL,                 SMTP_STATE_INITIAL | SMTP_STATE_EHLO | SMTP_STATE_MAIL_FROM | SMTP_STATE_RCPT_TO | SMTP_STATE_DATA },
  { "STARTTLS", smtp_request_STARTTLS,      smtp_response_STARTTLS, smtp_action_STARTTLS, SMTP_STATE_EHLO },
  { NULL, NULL, NULL, NULL, static_cast<SmtpStateTypes>(0) }
};

static struct _SmtpExtensionDesc known_extensions_table[] =
{
  { "PIPELINING", SMTP_EM_PIPELINING },
  { "SIZE",       SMTP_EM_SIZE       },
  { "ETRN",       SMTP_EM_ETRN       },
  { "8BITMIME",   SMTP_EM_8BITMIME   },
  { "AUTH",       SMTP_EM_AUTH       },
  { "STARTTLS",   SMTP_EM_STARTTLS   },
  { NULL,         static_cast<SmtpExtensionTypes>(0) }
};

GHashTable *known_commands;
GHashTable *known_extensions;

/**
 * smtp_init_cmd_hash:
 *
 * Called at module initialization time to fill the known commands hash.
 */
void
smtp_init_cmd_hash(void)
{
  gint i;

  /* known_commands is always looked up with an uppercase command */
  known_commands = g_hash_table_new(g_str_hash, g_str_equal);
  i = 0;
  while (known_commands_table[i].name != NULL)
    {
      g_hash_table_insert(known_commands, const_cast<char *>(known_commands_table[i].name), &known_commands_table[i]);
      i++;
    }
  known_extensions = g_hash_table_new(g_str_hash, g_str_equal);
  i = 0;
  while (known_extensions_table[i].name != NULL)
    {
      g_hash_table_insert(known_extensions, const_cast<char *>(known_extensions_table[i].name), &known_extensions_table[i]);
      i++;
    }
}
