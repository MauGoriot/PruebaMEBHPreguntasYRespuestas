using CapaPresentacion.Models;
using CapaPresentacion.utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Data.Entity;
using System.Web.Services.Description;

namespace CapaPresentacion.Controllers
{
    public class HomeController : Controller
    {
        private ApplicationDbContext db = new ApplicationDbContext();

        [ValidarSesion]
        public ActionResult Index()
        {
            var preguntas = db.Preguntas
                .Include(p => p.Usuario)
                .OrderByDescending(p => p.FechaCreacion)
                .Select(p => new PreguntaCantidad
                {
                    PreguntaID = p.PreguntaID,
                    Titulo = p.Titulo,
                    FechaCreacion = p.FechaCreacion,
                    Estado = p.Estado,
                    Usuario = p.Usuario,  // Incluimos el usuario
                    CantidadRespuestas = p.Respuestas.Count  // Contamos las respuestas
                })
                .ToList();

            return View(preguntas);
        }

        [ValidarSesion]
        public ActionResult MisPreguntas()
        {
            int usuarioID = ((Usuario)Session["usuario"]).UsuarioID;

            var misPreguntas = db.Preguntas
                .Where(p => p.UsuarioID == usuarioID)
                .OrderByDescending(p => p.FechaCreacion)
                .Select(p => new PreguntaCantidad
                {
                    PreguntaID = p.PreguntaID,
                    Titulo = p.Titulo,
                    FechaCreacion = p.FechaCreacion,
                    Estado = p.Estado,
                    CantidadRespuestas = p.Respuestas.Count  
                })
                .ToList();

            return View(misPreguntas);
        }


        public ActionResult CerrarSesion()
        {
            TempData["Mensaje"] = "Sesion cerrada";
            TempData["TipoMensaje"] = "success";
            Session["usuario"] = null;
            return RedirectToAction("Login","Acceso");
        }
    }
}