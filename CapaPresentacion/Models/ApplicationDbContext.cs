using System.Data.Entity; 
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace CapaPresentacion.Models
{
    public class ApplicationDbContext : DbContext
    {

        public ApplicationDbContext() : base("name=Connection")
        {
        }


        public DbSet<Usuario> Usuarios { get; set; }
        public DbSet<Pregunta> Preguntas { get; set; }
        public DbSet<Respuesta> Respuestas { get; set; }
    }
}