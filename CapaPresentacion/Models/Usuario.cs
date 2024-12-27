using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Web;


namespace CapaPresentacion.Models
{
    public class Usuario
    {
        public int UsuarioID { get; set; }
        public string NombreUsuario { get; set; }

        public string Rol { get; set; }

        [NotMapped]
        public string Clave { get; set; }

        [NotMapped]
        public string ConfirmarClave { get; set; }
    }
}