import HeroHeader from "@/components/HeroHeader";
import SkillsMatrix from "@/components/SkillsMatrix";
import ProjectShowcase from "@/components/ProjectShowcase";
import LabMetricsSidebar from "@/components/LabMetricsSidebar";

export default function Home() {
  return (
    <main className="max-w-7xl mx-auto px-6 lg:px-8 py-8 md:py-12 w-full relative">
      <HeroHeader />
      
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-12 lg:gap-16">
        <div className="lg:col-span-8 flex flex-col gap-12">
          <SkillsMatrix />
          <ProjectShowcase />
        </div>
        
        <div className="lg:col-span-4 relative h-full">
          {/* This component becomes a sticky sidebar on large screens (lg), 
              but acts as a stacked block below the projects on smaller screens.
              This allows you to see both layout paradigms depending on the device size! */}
          <LabMetricsSidebar />
        </div>
      </div>
      
      <footer className="mt-24 border-t border-slate-800/60 pt-8 pb-12 text-center text-slate-500 text-sm">
        <p>&copy; {new Date().getFullYear()} Keith Puthoor. All rights reserved.</p>
      </footer>
    </main>
  );
}
