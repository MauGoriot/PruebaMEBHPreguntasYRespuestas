using CapaPresentacion.Models;
using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Data;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Web.Mvc;
using CapaPresentacion.utils;
using System.Web.UI.WebControls;
using System.Text.RegularExpressions;

namespace CapaPresentacion.Controllers
{
    public class AccesoController : Controller
    {
        private ApplicationDbContext db = new ApplicationDbContext();

        // GET: Acceso
        public ActionResult Login()
        {
            return View();
        }

        public ActionResult Registrar()
        {
            return View();
        }

        [HttpPost]
        public ActionResult Registrar(Usuario oUsuario)
        {
            if (oUsuario.Clave != oUsuario.ConfirmarClave)
            {
                ViewData["Mensaje"] = "Las contraseñas no coinciden";
                ViewData["TipoMensaje"] = "error";
                return View();
            }

            if (oUsuario.Clave.Length < 6)
            {
                ViewData["Mensaje"] = "La contraseña debe tener al menos 6 caracteres";
                ViewData["TipoMensaje"] = "error";
                return View(oUsuario);
            }

            if (Evitar(oUsuario.Clave))
            {
                ViewData["Mensaje"] = "La contraseña contiene caracteres no permitidos";
                ViewData["TipoMensaje"] = "error";
                return View(oUsuario);
            }

            if (Evitar(oUsuario.NombreUsuario))
            {
                ViewData["Mensaje"] = "El nombre del usuario contiene caracteres no permitidos";
                ViewData["TipoMensaje"] = "error";
                return View(oUsuario);
            }

            string mensaje;
            bool registrado;

            try
            {
                oUsuario.Clave = Encriptador.ConvertirSha256(oUsuario.Clave);

                var nombreUsuarioParam = new SqlParameter("@NombreUsuario", oUsuario.NombreUsuario);
                var claveParam = new SqlParameter("@Clave", oUsuario.Clave);
                var registroParam = new SqlParameter("@Registro", SqlDbType.Bit)
                {
                    Direction = ParameterDirection.Output
                };
                var mensajeParam = new SqlParameter("@Mensaje", SqlDbType.NVarChar, 100)
                {
                    Direction = ParameterDirection.Output
                };


                db.Database.ExecuteSqlCommand(
                    "EXEC sp_RegistrarUsuario @NombreUsuario, @Clave, @Registro OUTPUT, @Mensaje OUTPUT",
                    nombreUsuarioParam, claveParam, registroParam, mensajeParam);

                registrado = Convert.ToBoolean(registroParam.Value);
                mensaje = mensajeParam.Value.ToString();

            }
            catch (Exception ex)
            {
                ViewData["Mensaje"] = "Ocurrió un error al registrar el usuario. Inténtalo de nuevo.";
                return View();
            }

            ViewData["Mensaje"] = mensaje;
            ViewData["TipoMensaje"] = "error";

            if (registrado)
            {
                TempData["Mensaje"] = mensaje;
                TempData["TipoMensaje"] = "success";
                return RedirectToAction("Login", "Acceso");
            }
            else
            {
                return View();
            }
        }

        [HttpPost]
        public ActionResult Login(Usuario oUsuario)
        {
            if (Evitar(oUsuario.Clave))
            {
                ViewData["Mensaje"] = "La contraseña contiene caracteres no permitidos";
                ViewData["TipoMensaje"] = "error";
                return View(oUsuario);
            }

            if (Evitar(oUsuario.NombreUsuario))
            {
                ViewData["Mensaje"] = "El nombre del usuario contiene caracteres no permitidos";
                ViewData["TipoMensaje"] = "error";
                return View(oUsuario);
            }

            oUsuario.Clave = Encriptador.ConvertirSha256(oUsuario.Clave);

            var resultado = db.Database.SqlQuery<Usuario>(
                "EXEC sp_ValidarUsuario @NombreUsuario, @Clave",
                new SqlParameter("@NombreUsuario", oUsuario.NombreUsuario),
                new SqlParameter("@Clave", oUsuario.Clave)
            ).FirstOrDefault();

            if (resultado != null && resultado.UsuarioID != 0)
            {
                Session["usuario"] = resultado;
                return RedirectToAction("Index", "Home");
            }
            else
            {
                ViewData["Mensaje"] = "Usuario no encontrado";
                ViewData["TipoMensaje"] = "Error";
            }

            return View();
        }

        public bool Evitar(string input)
        {

            string patron = @"[';<>\-]";
            return Regex.IsMatch(input, patron);
        }
    }
}