using CapaPresentacion.Models;
using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Data;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using CapaPresentacion.utils;

namespace CapaPresentacion.Controllers
{
    public class PreguntasController : Controller
    {
        private ApplicationDbContext db = new ApplicationDbContext();

        [ValidarSesion]
        [HttpPost]
        public ActionResult GuardarPregunta(Pregunta oPregunta) {
            if (ModelState.IsValid)
            {
                int usuarioID = ((Usuario)Session["usuario"]).UsuarioID;
                var usuarioParam = new SqlParameter("@UsuarioID", usuarioID);
                var tituloParam = new SqlParameter("@Titulo", oPregunta.Titulo);
                var mensajeParam = new SqlParameter("@Mensaje", SqlDbType.NVarChar, 255)
                {
                    Direction = ParameterDirection.Output
                };

                db.Database.ExecuteSqlCommand(
                    "EXEC sp_GuardarPregunta @UsuarioID, @Titulo, @Mensaje OUT",
                    usuarioParam,
                    tituloParam,
                    mensajeParam);

                string mensaje = mensajeParam.Value.ToString();

                if (mensaje == "Pregunta publicada correctamente.")
                {
                    TempData["Mensaje"] = mensaje;
                    TempData["TipoMensaje"] = "success"; 
                }
                else
                {
                    TempData["Mensaje"] = mensaje;
                    TempData["TipoMensaje"] = "error"; 
                }

                return RedirectToAction("Index", "Home");
            }
            else
            {
                return RedirectToAction("Index", "home");
            }
        }

        [HttpPost]
        public JsonResult ActualizarEstadoPregunta(int preguntaID, bool estado)
        {
            string mensaje = string.Empty;

            var preguntaIDParam = new SqlParameter("@PreguntaID", preguntaID);
            var nuevoEstadoParam = new SqlParameter("@NuevoEstado", estado ? 1 : 0);
            var mensajeParam = new SqlParameter("@Mensaje", System.Data.SqlDbType.NVarChar, 255)
            {
                Direction = System.Data.ParameterDirection.Output
            };

            db.Database.ExecuteSqlCommand(
                "EXEC sp_ActualizarEstadoPregunta @PreguntaID, @NuevoEstado, @Mensaje OUTPUT",
                preguntaIDParam,
                nuevoEstadoParam,
                mensajeParam);

            mensaje = mensajeParam.Value.ToString();

            return Json(new { success = true, message = mensaje });
        }
    }
}