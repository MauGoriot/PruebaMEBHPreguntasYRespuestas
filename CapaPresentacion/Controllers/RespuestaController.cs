using CapaPresentacion.Models;
using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Data;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using CapaPresentacion.utils;
using System.Data.Entity;

namespace CapaPresentacion.Controllers
{
    public class RespuestaController : Controller
    {
        private ApplicationDbContext db = new ApplicationDbContext();

        [ValidarSesion]
        public ActionResult Responder(Pregunta oPregunta)
        {

            var pregunta = db.Preguntas
                .Include(p => p.Usuario)
                .FirstOrDefault(p => p.PreguntaID == oPregunta.PreguntaID);

            if (pregunta == null)
            {
                return HttpNotFound();
            }

            var respuestas = db.Respuestas
                .Where(r => r.PreguntaID == oPregunta.PreguntaID)
                .Include(r => r.Usuario)
                .OrderByDescending(p => p.FechaCreacion)
                .ToList();

            var preguntaRespuestas = new PreguntaRespuesta
            {
                Pregunta = pregunta,
                Respuestas = respuestas
            };

            return View(preguntaRespuestas);
        }

        [ValidarSesion]
        [HttpPost]
        public ActionResult GuardarRespuesta(Respuesta oRespuesta)
        {
            if (ModelState.IsValid)
            {
                int usuarioID = ((Usuario)Session["usuario"]).UsuarioID;
                var usuarioParam = new SqlParameter("@UsuarioID", usuarioID);
                var preguntaParam = new SqlParameter("@PreguntaID", oRespuesta.PreguntaID);
                var contenifoParam = new SqlParameter("@Contenido", oRespuesta.Contenido);
                var mensajeParam = new SqlParameter("@Mensaje", SqlDbType.NVarChar, 255)
                {
                    Direction = ParameterDirection.Output
                };

                db.Database.ExecuteSqlCommand(
                    "EXEC sp_InsertarRespuesta @PreguntaID, @UsuarioID, @Contenido, @Mensaje OUT",
                    preguntaParam,
                    usuarioParam,
                    contenifoParam,
                    mensajeParam);

                string mensaje = mensajeParam.Value.ToString();

                if (!string.IsNullOrEmpty(mensaje))
                {
                    TempData["Mensaje"] = mensaje;
                    TempData["TipoMensaje"] = "success";
                   
                }
                else
                {
                    mensaje = "Error al guardar la respuesta";
                    TempData["Mensaje"] = mensaje;
                    TempData["TipoMensaje"] = "error";
                }

                return RedirectToAction("Responder", "Respuesta", new { PreguntaID = oRespuesta.PreguntaID });
            }
            else
            {
                return RedirectToAction("Responder", "Respuesta", new { PreguntaID = oRespuesta.PreguntaID });
            }

        }

    }
}