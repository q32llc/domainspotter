import logging

from openai import AsyncOpenAI
from pydantic import BaseModel

from .models import Domains, Idea

log = logging.getLogger(__name__)


class DomainSearch:
    def __init__(self, openai_client: AsyncOpenAI):
        self.openai = openai_client

    async def get_questions(self, idea: Idea) -> Idea:
        """Generate questions for a domain idea using GPT-4.1-mini and save them to the database"""
        system_prompt = """
        You are a helpful assistant that generates questions for a domain idea.

        You are an expert in domain names and the best practices for naming a business.
        """

        prompt = f"""Given this domain idea, reply with a short list of 2 or 3 additional questions you need answered to
          search for domains.

          If you have enough information, reply with an empty array.

          Examples might be the needed length, or whether it should be business or quirky, or whether it should be a .com only or
          if acceptable tlds include .io or .ai, etc.

Name: {idea.name}
Description: {idea.state.get('description', '')}

Reply with a JSON array of questions, example reply:
{{"questions": ["What is the name of the business?", "What is the name of the business?"]}}
"""

        try:

            class Questions(BaseModel):
                questions: list[str]

            response = await self.openai.beta.chat.completions.parse(
                model="gpt-4.1-mini",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt},
                ],
                response_format=Questions,
            )

            questions: Questions = response.choices[0].message.parsed
            idea.state["questions"] = questions.questions
            return idea
        except Exception as e:
            log.error(f"Failed to generate questions for idea {idea.id}: {e}")
            raise e

    async def get_domain_names(self, idea: Idea) -> Domains:
        """Generate domain names for a domain idea using GPT-4.1-mini and save them to the database"""
        system_prompt = """
        You are a helpful assistant that generates domain names for a domain idea.

        You are an expert in domain names and the best practices for naming a business.
        """

        questions = idea.state.get("questions", [])
        if questions:
            extra_prompt = f"""
            Here are some questions that have been answered to help you generate domain names:
            {questions}
            """
        else:
            extra_prompt = ""

        prompt = f"""Given this domain idea, reply with 100 domain name suggestions, including tlds,
          sort them by popularity and relevance and likelihood to be available.

          The domain name should be a single word, not a phrase.

          Dashes are generally ok, but they weaken the quality of the domain name.
          Numbers too are generally ok, but they weaken the quality of the domain name.
          Shorter is generally better.
          Sometimes neologisms are cool.
          Try to stay away from trendy words, unless they are a very good fit for the business.
          Insider terms are good.
          Try to stay away from obscure words, unless they are a very good fit for the business.
          Drawing on other languages is good.
          Try to stay away from words that are hard to pronounce, speak, or spell.

          Name: {idea.name}
          Description: {idea.state.get('description', '')}
          {extra_prompt}

          IMPORTANT: Reply with a JSON object containing a list of domains, where each domain has exactly two fields:
          - domain: string (the domain name with TLD)
          - reason: string (explanation of why this domain is a good fit)

          Example response format:
          {{
            "domains": [
              {{
                "domain": "example.com",
                "reason": "This is a clear and professional domain name"
              }},
              {{
                "domain": "example.io",
                "reason": "Modern TLD that fits tech startups"
              }}
            ]
          }}
        """

        try:
            response = await self.openai.beta.chat.completions.parse(
                model="gpt-4.1-mini",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt},
                ],
                response_format=Domains,
            )

            domains: Domains = response.choices[0].message.parsed
            return domains
        except Exception as e:
            log.error(f"Failed to generate domain names for idea {idea.id}: {e}")
            log.error(
                f"Response content: {response.choices[0].message.content if 'response' in locals() else 'No response'}"
            )
            raise e
