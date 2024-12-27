using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace CapaPresentacion.Models
{
    public class Respuesta
    {
        public int RespuestaID { get; set; }
        public int PreguntaID { get; set; }
        public int UsuarioID { get; set; }
        public string Contenido { get; set; }
        public DateTime FechaCreacion { get; set; }
        public virtual Pregunta Pregunta { get; set; }
        public virtual Usuario Usuario { get; set; }
    }
}