using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace CapaPresentacion.Models
{
    public class PreguntaCantidad
    {
        public int PreguntaID { get; set; }
        public string Titulo { get; set; }
        public DateTime FechaCreacion { get; set; }
        public bool Estado { get; set; }
        public Usuario Usuario { get; set; }  
        public int CantidadRespuestas { get; set; }  
    }
}