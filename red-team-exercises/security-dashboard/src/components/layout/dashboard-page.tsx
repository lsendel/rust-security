import { motion } from 'framer-motion'

interface DashboardPageProps {
  title: string;
  description: string;
  headerContent?: React.ReactNode;
  metrics: React.ReactNode;
  tabs: React.ReactNode;
}

export function DashboardPage({ title, description, headerContent, metrics, tabs }: DashboardPageProps) {
  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        staggerChildren: 0.1
      }
    }
  }

  return (
    <div className="flex-1 space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">{title}</h1>
          <p className="text-muted-foreground">{description}</p>
        </div>
        <div className="flex items-center space-x-2">
          {headerContent}
        </div>
      </div>

      {/* Key Metrics Cards */}
      <motion.div
        variants={containerVariants}
        initial="hidden"
        animate="visible"
        className="grid gap-4 md:grid-cols-2 lg:grid-cols-4"
      >
        {metrics}
      </motion.div>

      {/* Main Content Tabs */}
      {tabs}
    </div>
  )
}
