using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace CapaPresentacion.Models
{
    public class Pregunta
    {
        public int PreguntaID { get; set; }
        public int UsuarioID { get; set; } 
        public string Titulo { get; set; }
        public DateTime FechaCreacion { get; set; }
        public bool Estado { get; set; }
        public virtual Usuario Usuario { get; set; }
        public virtual ICollection<Respuesta> Respuestas { get; set; }
    }
}