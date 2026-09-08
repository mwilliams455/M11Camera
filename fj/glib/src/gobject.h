#ifndef R2A_COMPILE_ONLY_GOBJECT_H
#define R2A_COMPILE_ONLY_GOBJECT_H

/*
 * Compile-only compatibility declarations for the incomplete public Milbeaut
 * source snapshot pinned by the R2A workflow.
 *
 * MILB_API/include/glib-object.h resolves ../../../fj/glib/src/gobject.h,
 * but that external ETK/GLib tree is not present in ZMlogicL/companyTask at
 * f5fc84bd5c475f4c15017b7bff749f81c3618287.  The two fingerprint target
 * translation units include it only transitively through ddarm.h -> ddtop.h
 * -> kchiptop*.h.  Their gamma/R2Y code does not depend on GObject runtime
 * state.  Keep this file declaration-only: it exists solely to let the exact
 * pinned headers parse under the historical compiler.
 */

#ifdef __cplusplus
# define G_BEGIN_DECLS extern "C" {
# define G_END_DECLS }
#else
# define G_BEGIN_DECLS
# define G_END_DECLS
#endif

#if defined(__GNUC__)
# define G_GNUC_CONST __attribute__((__const__))
#else
# define G_GNUC_CONST
#endif

typedef signed char gint8;
typedef unsigned char guint8;
typedef unsigned char guchar;
typedef signed short gint16;
typedef unsigned short guint16;
typedef unsigned short gushort;
typedef signed int gint;
typedef unsigned int guint;
typedef signed int gint32;
typedef unsigned int guint32;
typedef signed long glong;
typedef unsigned long gulong;
typedef signed long long gint64;
typedef unsigned long long guint64;
typedef char gchar;
typedef void *gpointer;
typedef const void *gconstpointer;
typedef int gboolean;
typedef unsigned long GType;

typedef struct _GTypeInstance { gpointer g_class; } GTypeInstance;
typedef struct _GTypeClass { GType g_type; } GTypeClass;
typedef struct _GObject { gpointer r2a_opaque; } GObject;
typedef struct _GObjectClass { gpointer r2a_opaque; } GObjectClass;

#ifndef TRUE
# define TRUE 1
#endif
#ifndef FALSE
# define FALSE 0
#endif

#define G_TYPE_CHECK_INSTANCE_CAST(instance, g_type, c_type) ((c_type *)(instance))
#define G_TYPE_CHECK_CLASS_CAST(class, g_type, c_type) ((c_type *)(class))
#define G_TYPE_CHECK_INSTANCE_TYPE(instance, g_type) (1)
#define G_TYPE_CHECK_CLASS_TYPE(class, g_type) (1)
#define G_TYPE_INSTANCE_GET_CLASS(instance, g_type, c_type) ((c_type *)0)
#define G_TYPE_INSTANCE_GET_PRIVATE(instance, g_type, c_type) ((c_type *)0)
#define G_OBJECT(object) ((GObject *)(object))
#define G_OBJECT_CLASS(class) ((GObjectClass *)(class))

#endif /* R2A_COMPILE_ONLY_GOBJECT_H */
