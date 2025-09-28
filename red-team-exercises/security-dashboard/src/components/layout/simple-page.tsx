import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'

interface SimplePageProps {
  title: string;
  description: string;
  cardTitle: string;
  cardDescription?: string;
  children: React.ReactNode;
}

export function SimplePage({ title, description, cardTitle, cardDescription, children }: SimplePageProps) {
  return (
    <div className="flex-1 space-y-6 p-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">{title}</h1>
        <p className="text-muted-foreground">{description}</p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>{cardTitle}</CardTitle>
          {cardDescription && <CardDescription>{cardDescription}</CardDescription>}
        </CardHeader>
        <CardContent>
          {children}
        </CardContent>
      </Card>
    </div>
  )
}
